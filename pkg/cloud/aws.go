package cloud

import (
	"context"
	"fmt"
	"net"
	"strings"

	"ztap/pkg/logging"
	"ztap/pkg/policy"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ec2API captures the EC2 operations used by ZTAP. Defining an interface allows
// us to provide a lightweight mock implementation during testing while using the
// real AWS SDK client in production.
type ec2API interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	AuthorizeSecurityGroupEgress(ctx context.Context, params *ec2.AuthorizeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error)
}

// AWSClient manages AWS Security Group synchronization
type AWSClient struct {
	ec2API ec2API
	region string
}

// Resource represents a discovered cloud resource
type Resource struct {
	ID        string
	Name      string
	Type      string
	PrivateIP string
	PublicIP  string
	Labels    map[string]string
}

// AWSOptions customizes AWS client initialization.
type AWSOptions struct {
	Region  string
	Profile string
}

// AWSPolicySyncOptions controls how policy synchronization behaves.
type AWSPolicySyncOptions struct {
	DryRun        bool
	ReplaceEgress bool
	Inventory     []Resource // Optional: inject pre-discovered resources to skip API calls
}

// AWSSyncResult summarizes a sync operation.
type AWSSyncResult struct {
	Desired         int
	ResolvedTargets int
	ToAuthorize     int
	ToRevoke        int
	ToUpdate        int
}

const (
	awsRuleDescriptionPrefix = "ztap:policy="
)

// NewAWSClient creates a new AWS client
func NewAWSClient(ctx context.Context, region string) (*AWSClient, error) {
	return NewAWSClientWithOptions(ctx, AWSOptions{Region: region})
}

// NewAWSClientWithOptions creates a new AWS client with optional overrides.
func NewAWSClientWithOptions(ctx context.Context, opts AWSOptions) (*AWSClient, error) {
	loadOpts := make([]func(*config.LoadOptions) error, 0, 2)
	region := strings.TrimSpace(opts.Region)
	if region != "" {
		loadOpts = append(loadOpts, config.WithRegion(region))
	}
	profile := strings.TrimSpace(opts.Profile)
	if profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if region == "" {
		region = cfg.Region
	}

	return &AWSClient{
		ec2API: ec2.NewFromConfig(cfg),
		region: region,
	}, nil
}

// DiscoverResources finds all EC2 instances and their metadata
func (c *AWSClient) DiscoverResources(ctx context.Context) ([]Resource, error) {
	input := &ec2.DescribeInstancesInput{}
	result, err := c.ec2API.DescribeInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	// Pre-allocate with estimated capacity
	estimatedCapacity := 0
	for _, reservation := range result.Reservations {
		estimatedCapacity += len(reservation.Instances)
	}
	resources := make([]Resource, 0, estimatedCapacity)

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State != nil && instance.State.Name == types.InstanceStateNameTerminated {
				continue
			}

			// Pre-allocate labels map
			labels := make(map[string]string, len(instance.Tags))
			var name string
			for _, tag := range instance.Tags {
				key := aws.ToString(tag.Key)
				value := aws.ToString(tag.Value)
				if key == "Name" {
					name = value
				}
				labels[key] = value
			}

			privateIP := aws.ToString(instance.PrivateIpAddress)
			publicIP := aws.ToString(instance.PublicIpAddress)

			resources = append(resources, Resource{
				ID:        aws.ToString(instance.InstanceId),
				Name:      name,
				Type:      "EC2",
				PrivateIP: privateIP,
				PublicIP:  publicIP,
				Labels:    labels,
			})
		}
	}

	return resources, nil
}

// SyncPolicy converts ZTAP policy to AWS Security Group rules.
func (c *AWSClient) SyncPolicy(ctx context.Context, p policy.NetworkPolicy, sgID string) error {
	_, err := c.SyncPolicyWithOptions(ctx, p, sgID, AWSPolicySyncOptions{})
	return err
}

// SyncPolicyWithOptions converts a policy into AWS Security Group rules and reconciles them.
func (c *AWSClient) SyncPolicyWithOptions(ctx context.Context, p policy.NetworkPolicy, sgID string, opts AWSPolicySyncOptions) (*AWSSyncResult, error) {
	safeName := sanitizePolicyName(p.Metadata.Name)
	logging.Infof("Syncing policy '%s' to Security Group %s", safeName, sgID)

	if len(p.Spec.Ingress) > 0 {
		logging.Warnf("policy %s: ingress rules are ignored by AWS SG sync", safeName)
	}

	var resources []Resource
	if hasEgressSelectors(p) {
		if opts.Inventory != nil {
			resources = opts.Inventory
		} else {
			var err error
			resources, err = c.DiscoverResources(ctx)
			if err != nil {
				return nil, fmt.Errorf("discovering AWS resources: %w", err)
			}
		}
	}

	managedPrefix := awsPolicyDescriptionPrefix(safeName)
	desired, resolvedTargets, err := buildAWSEgressRules(p, resources)
	if err != nil {
		return nil, err
	}

	managedExisting, allExisting, err := c.loadExistingEgressRules(ctx, sgID, managedPrefix)
	if err != nil {
		return nil, err
	}

	toAuthorize := make([]awsRuleKey, 0)
	if opts.ReplaceEgress {
		// Takeover mode revokes all egress first, so all desired rules must be re-added.
		toAuthorize = make([]awsRuleKey, 0, len(desired))
		for key := range desired {
			toAuthorize = append(toAuthorize, key)
		}
	} else {
		for key := range desired {
			if _, ok := managedExisting[key]; !ok {
				toAuthorize = append(toAuthorize, key)
			}
		}
	}

	toRevoke := make([]awsRuleKey, 0)
	for key := range managedExisting {
		if _, ok := desired[key]; !ok {
			toRevoke = append(toRevoke, key)
		}
	}

	result := &AWSSyncResult{
		Desired:         len(desired),
		ResolvedTargets: resolvedTargets,
		ToAuthorize:     len(toAuthorize),
		ToRevoke:        len(toRevoke),
		ToUpdate:        0,
	}
	if opts.ReplaceEgress {
		result.ToRevoke = len(allExisting)
	}

	if opts.DryRun {
		if opts.ReplaceEgress {
			logging.Infof("[dry-run] would revoke all egress rules in %s", sgID)
		} else {
			for _, key := range toRevoke {
				logging.Infof("[dry-run] would revoke rule %s:%d-%d -> %s", key.protocol, key.fromPort, key.toPort, key.cidr)
			}
		}
		for _, key := range toAuthorize {
			logging.Infof("[dry-run] would authorize rule %s:%d-%d -> %s", key.protocol, key.fromPort, key.toPort, key.cidr)
		}
		return result, nil
	}

	if opts.ReplaceEgress {
		if err := c.RevokeAllEgress(ctx, sgID); err != nil {
			return result, err
		}
	}

	for _, key := range toAuthorize {
		perm := key.permissionWithDescription(managedPrefix)
		if err := c.authorizeEgressPermission(ctx, sgID, perm); err != nil {
			return result, err
		}
	}

	if !opts.ReplaceEgress {
		for _, key := range toRevoke {
			perm := key.permissionWithoutDescription()
			if err := c.revokeEgressPermission(ctx, sgID, perm); err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

// authorizeEgress adds an egress rule to the Security Group
func (c *AWSClient) authorizeEgress(ctx context.Context, sgID, cidr, protocol string, startPort int, endPort int) error {
	// Convert protocol to lowercase (AWS uses lowercase)
	proto := strings.ToLower(protocol)
	if startPort < 0 || startPort > 65535 {
		return fmt.Errorf("invalid port %d", startPort)
	}
	if endPort < 0 || endPort > 65535 {
		return fmt.Errorf("invalid port %d", endPort)
	}
	if endPort < startPort {
		return fmt.Errorf("invalid port range %d-%d", startPort, endPort)
	}
	if endPort == 0 {
		endPort = startPort
	}
	pFrom := int32(startPort) // #nosec G115 -- port is validated to be within uint16 range
	pTo := int32(endPort)     // #nosec G115 -- port is validated to be within uint16 range

	// Note: AWS Security Groups are stateful, so egress rules automatically allow responses
	perm := types.IpPermission{
		IpProtocol: aws.String(proto),
		FromPort:   aws.Int32(pFrom),
		ToPort:     aws.Int32(pTo),
		IpRanges: []types.IpRange{
			{
				CidrIp:      aws.String(cidr),
				Description: aws.String(awsRuleDescriptionPrefix + "legacy"),
			},
		},
	}

	if err := c.authorizeEgressPermission(ctx, sgID, perm); err != nil {
		return err
	}
	logging.Infof("Authorized egress: %s:%d-%d -> %s in %s", protocol, startPort, endPort, cidr, sgID)
	return nil
}

// RevokeAllEgress removes all egress rules from a Security Group (for cleanup)
func (c *AWSClient) RevokeAllEgress(ctx context.Context, sgID string) error {
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	}

	result, err := c.ec2API.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe security group: %w", err)
	}

	if len(result.SecurityGroups) == 0 {
		return fmt.Errorf("security group %s not found", sgID)
	}

	sg := result.SecurityGroups[0]
	if len(sg.IpPermissionsEgress) == 0 {
		return nil
	}

	revokeInput := &ec2.RevokeSecurityGroupEgressInput{
		GroupId:       aws.String(sgID),
		IpPermissions: sg.IpPermissionsEgress,
	}

	_, err = c.ec2API.RevokeSecurityGroupEgress(ctx, revokeInput)
	if err != nil {
		return fmt.Errorf("failed to revoke egress rules: %w", err)
	}

	logging.Infof("Revoked all egress rules from %s", sgID)
	return nil
}

type awsRuleKey struct {
	protocol string
	fromPort int32
	toPort   int32
	cidr     string
	ipv6     bool
}

func (k awsRuleKey) permissionWithDescription(desc string) types.IpPermission {
	perm := types.IpPermission{
		IpProtocol: aws.String(k.protocol),
		FromPort:   aws.Int32(k.fromPort),
		ToPort:     aws.Int32(k.toPort),
	}
	if k.ipv6 {
		perm.Ipv6Ranges = []types.Ipv6Range{{CidrIpv6: aws.String(k.cidr), Description: aws.String(desc)}}
		return perm
	}
	perm.IpRanges = []types.IpRange{{CidrIp: aws.String(k.cidr), Description: aws.String(desc)}}
	return perm
}

func (k awsRuleKey) permissionWithoutDescription() types.IpPermission {
	perm := types.IpPermission{
		IpProtocol: aws.String(k.protocol),
		FromPort:   aws.Int32(k.fromPort),
		ToPort:     aws.Int32(k.toPort),
	}
	if k.ipv6 {
		perm.Ipv6Ranges = []types.Ipv6Range{{CidrIpv6: aws.String(k.cidr)}}
		return perm
	}
	perm.IpRanges = []types.IpRange{{CidrIp: aws.String(k.cidr)}}
	return perm
}

func awsPolicyDescriptionPrefix(policyName string) string {
	safe := sanitizePolicyName(policyName)
	if safe == "" {
		safe = "policy"
	}
	return awsRuleDescriptionPrefix + safe
}

func buildAWSEgressRules(p policy.NetworkPolicy, resources []Resource) (map[awsRuleKey]struct{}, int, error) {
	desired := make(map[awsRuleKey]struct{})
	resolvedTargets := 0

	for _, egress := range p.Spec.Egress {
		cidr := strings.TrimSpace(egress.To.IPBlock.CIDR)
		selector := egress.To.PodSelector
		if !selectorEmpty(egress.To.NamespaceSelector) {
			return nil, 0, fmt.Errorf("namespaceSelector is not supported for AWS security group rules")
		}

		if cidr == "" && selectorEmpty(selector) {
			continue
		}

		var cidrs []string
		if cidr != "" {
			cidrs = []string{cidr}
		} else {
			ips := resolvePrivateAddresses(resources, selector)
			if len(ips) == 0 {
				return nil, 0, fmt.Errorf("podSelector %v resolved to no addresses", selector)
			}
			resolvedTargets += len(ips)
			resolved, err := ipsToHostCIDRs(ips)
			if err != nil {
				return nil, 0, err
			}
			cidrs = resolved
		}

		for _, port := range egress.Ports {
			if port.PortName != "" {
				return nil, 0, fmt.Errorf("named ports are not supported for AWS security group rules")
			}
			start := port.Port
			end := port.Port
			if port.EndPort != nil {
				end = *port.EndPort
			}
			if err := validateAWSPortRange(start, end); err != nil {
				return nil, 0, err
			}
			proto := strings.ToLower(strings.TrimSpace(port.Protocol))
			if proto == "" {
				return nil, 0, fmt.Errorf("protocol is required")
			}
			for _, targetCIDR := range cidrs {
				key, err := awsRuleKeyFor(targetCIDR, proto, start, end)
				if err != nil {
					return nil, 0, err
				}
				desired[key] = struct{}{}
			}
		}
	}

	return desired, resolvedTargets, nil
}

func (c *AWSClient) loadExistingEgressRules(ctx context.Context, sgID, descPrefix string) (map[awsRuleKey]struct{}, map[awsRuleKey]struct{}, error) {
	input := &ec2.DescribeSecurityGroupsInput{GroupIds: []string{sgID}}
	result, err := c.ec2API.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to describe security group: %w", err)
	}
	if result == nil || len(result.SecurityGroups) == 0 {
		return nil, nil, fmt.Errorf("security group %s not found", sgID)
	}

	managed := make(map[awsRuleKey]struct{})
	all := make(map[awsRuleKey]struct{})
	for _, perm := range result.SecurityGroups[0].IpPermissionsEgress {
		proto := strings.ToLower(strings.TrimSpace(aws.ToString(perm.IpProtocol)))
		if perm.FromPort == nil || perm.ToPort == nil {
			continue
		}
		from := *perm.FromPort
		to := *perm.ToPort
		for _, r := range perm.IpRanges {
			cidr := strings.TrimSpace(aws.ToString(r.CidrIp))
			if cidr == "" {
				continue
			}
			key := awsRuleKey{protocol: proto, fromPort: from, toPort: to, cidr: cidr}
			all[key] = struct{}{}
			if isManagedDescription(aws.ToString(r.Description), descPrefix) {
				managed[key] = struct{}{}
			}
		}
		for _, r := range perm.Ipv6Ranges {
			cidr := strings.TrimSpace(aws.ToString(r.CidrIpv6))
			if cidr == "" {
				continue
			}
			key := awsRuleKey{protocol: proto, fromPort: from, toPort: to, cidr: cidr, ipv6: true}
			all[key] = struct{}{}
			if isManagedDescription(aws.ToString(r.Description), descPrefix) {
				managed[key] = struct{}{}
			}
		}
	}

	return managed, all, nil
}

func isManagedDescription(desc, prefix string) bool {
	trimmed := strings.TrimSpace(desc)
	if trimmed == "" {
		return false
	}
	return strings.HasPrefix(trimmed, prefix)
}

func resolvePrivateAddresses(resources []Resource, selector policy.PodSelectorSpec) []string {
	addrs := make([]string, 0)
	for _, r := range resources {
		if policy.MatchesSelector(r.Labels, selector) {
			if r.PrivateIP != "" {
				addrs = append(addrs, r.PrivateIP)
			}
		}
	}

	uniq := make(map[string]struct{}, len(addrs))
	dedup := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := uniq[a]; ok {
			continue
		}
		uniq[a] = struct{}{}
		dedup = append(dedup, a)
	}
	return dedup
}

func selectorEmpty(selector policy.PodSelectorSpec) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

func hasEgressSelectors(p policy.NetworkPolicy) bool {
	for _, e := range p.Spec.Egress {
		if !selectorEmpty(e.To.PodSelector) || !selectorEmpty(e.To.NamespaceSelector) {
			return true
		}
	}
	return false
}

func validateAWSPortRange(start int, end int) error {
	if start <= 0 || start > 65535 {
		return fmt.Errorf("invalid port %d", start)
	}
	if end <= 0 || end > 65535 {
		return fmt.Errorf("invalid port %d", end)
	}
	if end < start {
		return fmt.Errorf("invalid port range %d-%d", start, end)
	}
	return nil
}

func awsRuleKeyFor(cidr, protocol string, start, end int) (awsRuleKey, error) {
	trimmed := strings.TrimSpace(cidr)
	var ipv6 bool
	if strings.Contains(trimmed, "/") {
		ip, _, err := net.ParseCIDR(trimmed)
		if err != nil {
			return awsRuleKey{}, fmt.Errorf("invalid cidr %s", cidr)
		}
		ipv6 = ip.To4() == nil
	} else {
		ip := net.ParseIP(trimmed)
		if ip == nil {
			return awsRuleKey{}, fmt.Errorf("invalid cidr %s", cidr)
		}
		ipv6 = ip.To4() == nil
	}
	fromPort, err := portToInt32(start)
	if err != nil {
		return awsRuleKey{}, err
	}
	toPort, err := portToInt32(end)
	if err != nil {
		return awsRuleKey{}, err
	}
	proto := strings.ToLower(strings.TrimSpace(protocol))
	key := awsRuleKey{
		protocol: proto,
		fromPort: fromPort,
		toPort:   toPort,
		cidr:     trimmed,
		ipv6:     ipv6,
	}
	return key, nil
}

func portToInt32(port int) (int32, error) {
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %d", port)
	}
	return int32(port), nil
}

func ipsToHostCIDRs(ips []string) ([]string, error) {
	if len(ips) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, raw := range ips {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parsed := net.ParseIP(raw)
		if parsed == nil {
			return nil, fmt.Errorf("%q is not a valid IP address", raw)
		}
		if v4 := parsed.To4(); v4 != nil {
			ipStr := v4.String()
			if _, ok := seen[ipStr]; ok {
				continue
			}
			seen[ipStr] = struct{}{}
			out = append(out, ipStr+"/32")
			continue
		}
		if v6 := parsed.To16(); v6 != nil {
			ipStr := v6.String()
			if _, ok := seen[ipStr]; ok {
				continue
			}
			seen[ipStr] = struct{}{}
			out = append(out, ipStr+"/128")
			continue
		}
		return nil, fmt.Errorf("%q is not a valid IP address", raw)
	}
	return out, nil
}

func (c *AWSClient) authorizeEgressPermission(ctx context.Context, sgID string, perm types.IpPermission) error {
	input := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       aws.String(sgID),
		IpPermissions: []types.IpPermission{perm},
	}

	_, err := c.ec2API.AuthorizeSecurityGroupEgress(ctx, input)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}

	return nil
}

func (c *AWSClient) revokeEgressPermission(ctx context.Context, sgID string, perm types.IpPermission) error {
	input := &ec2.RevokeSecurityGroupEgressInput{
		GroupId:       aws.String(sgID),
		IpPermissions: []types.IpPermission{perm},
	}
	_, err := c.ec2API.RevokeSecurityGroupEgress(ctx, input)
	if err != nil {
		return err
	}
	return nil
}

const (
	// Capacity estimates for pre-allocation
	minResourceMatchCapacity     = 4
	defaultResourceMatchFraction = 10 // Expect 1/10 (10%) of resources to match
)

// MatchResourcesByLabels finds resources matching the given labels
func MatchResourcesByLabels(resources []Resource, labels map[string]string) []Resource {
	// Pre-allocate with conservative capacity estimate
	// Start with 10% of resources or minimum of 4 items
	estimatedMatches := len(resources) / defaultResourceMatchFraction
	if estimatedMatches < minResourceMatchCapacity {
		estimatedMatches = minResourceMatchCapacity
	}
	if estimatedMatches > len(resources) {
		estimatedMatches = len(resources)
	}
	matched := make([]Resource, 0, estimatedMatches)

	for _, r := range resources {
		// Early exit optimization: check if resource has at least as many labels
		if len(r.Labels) < len(labels) {
			continue
		}

		match := true
		for key, value := range labels {
			if r.Labels[key] != value {
				match = false
				break
			}
		}
		if match {
			matched = append(matched, r)
		}
	}
	return matched
}
