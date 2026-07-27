package cloud

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strings"

	"ztap/pkg/logging"
	"ztap/pkg/policy"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

const (
	defaultGCPRulePrefix   = "ztap-"
	defaultGCPPriorityBase = int32(2000)
	maxGCPPriority         = int32(65535)
	gcpRuleDescription     = "Managed by ZTAP"
)

type firewallsClient interface {
	List(ctx context.Context, projectID, networkURL string) ([]*computepb.Firewall, error)
	Insert(ctx context.Context, projectID string, rule *computepb.Firewall) error
	Patch(ctx context.Context, projectID string, rule *computepb.Firewall) error
	Delete(ctx context.Context, projectID, name string) error
}

type instancesClient interface {
	AggregatedList(ctx context.Context, projectID string) ([]*computepb.Instance, error)
}

type gcpFirewallsClient struct {
	client *compute.FirewallsClient
}

func (c *gcpFirewallsClient) List(ctx context.Context, projectID, networkURL string) ([]*computepb.Firewall, error) {
	it := c.client.List(ctx, &computepb.ListFirewallsRequest{
		Project: projectID,
		Filter:  new(fmt.Sprintf("network=\"%s\"", networkURL)),
	})

	var rules []*computepb.Firewall
	for {
		fw, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		rules = append(rules, fw)
	}

	return rules, nil
}

func (c *gcpFirewallsClient) Insert(ctx context.Context, projectID string, rule *computepb.Firewall) error {
	op, err := c.client.Insert(ctx, &computepb.InsertFirewallRequest{Project: projectID, FirewallResource: rule})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (c *gcpFirewallsClient) Patch(ctx context.Context, projectID string, rule *computepb.Firewall) error {
	op, err := c.client.Patch(ctx, &computepb.PatchFirewallRequest{Project: projectID, Firewall: rule.GetName(), FirewallResource: rule})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

func (c *gcpFirewallsClient) Delete(ctx context.Context, projectID, name string) error {
	op, err := c.client.Delete(ctx, &computepb.DeleteFirewallRequest{Project: projectID, Firewall: name})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

type gcpInstancesClient struct {
	client *compute.InstancesClient
}

func (c *gcpInstancesClient) AggregatedList(ctx context.Context, projectID string) ([]*computepb.Instance, error) {
	it := c.client.AggregatedList(ctx, &computepb.AggregatedListInstancesRequest{Project: projectID})

	var instances []*computepb.Instance
	for {
		pair, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		if pair.Value == nil {
			continue
		}
		instances = append(instances, pair.Value.Instances...)
	}

	return instances, nil
}

// GCPOptions customizes GCP client behavior.
type GCPOptions struct {
	RulePrefix   string
	PriorityBase int32
}

// GCPClient manages GCP VPC firewall synchronization.
type GCPClient struct {
	firewalls    firewallsClient
	instances    instancesClient
	rulePrefix   string
	priorityBase int32
}

// NewGCPClient creates a new GCP client using Application Default Credentials.
func NewGCPClient(ctx context.Context, opts GCPOptions) (*GCPClient, error) {
	fwClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcp firewalls client: %w", err)
	}

	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcp instances client: %w", err)
	}

	rulePrefix := strings.ToLower(strings.TrimSpace(opts.RulePrefix))
	if rulePrefix == "" {
		rulePrefix = defaultGCPRulePrefix
	}

	priorityBase := opts.PriorityBase
	if priorityBase <= 0 {
		priorityBase = defaultGCPPriorityBase
	}

	return &GCPClient{
		firewalls:    &gcpFirewallsClient{client: fwClient},
		instances:    &gcpInstancesClient{client: instancesClient},
		rulePrefix:   rulePrefix,
		priorityBase: priorityBase,
	}, nil
}

// GCPPolicySyncOptions controls how SyncPolicyWithOptions behaves.
type GCPPolicySyncOptions struct {
	DryRun bool
}

// SyncPolicy converts a ZTAP policy into GCP firewall rules and reconciles them.
func (c *GCPClient) SyncPolicy(ctx context.Context, p policy.NetworkPolicy, projectID, network string) error {
	return c.SyncPolicyWithOptions(ctx, p, projectID, network, GCPPolicySyncOptions{})
}

// DiscoverResources lists GCE instances for the specified project/network.
func (c *GCPClient) DiscoverResources(ctx context.Context, projectID, network string) ([]Resource, error) {
	if c.instances == nil {
		return nil, fmt.Errorf("gcp instances client not configured for discovery")
	}
	networkURL := networkSelfLink(projectID, network)
	return c.discoverResources(ctx, projectID, networkURL)
}

// CountManagedFirewalls counts the total firewalls and managed firewalls in a network.
// Returns (totalCount, managedCount, nil) on success.
func (c *GCPClient) CountManagedFirewalls(ctx context.Context, projectID, network string) (int, int, error) {
	networkURL := networkSelfLink(projectID, network)
	rules, err := c.firewalls.List(ctx, projectID, networkURL)
	if err != nil {
		return 0, 0, fmt.Errorf("listing firewall rules: %w", err)
	}

	total := len(rules)
	managed := 0
	for _, rule := range rules {
		if rule.Name != nil && strings.HasPrefix(*rule.Name, c.rulePrefix) {
			managed++
		}
	}

	return total, managed, nil
}

// ListManagedFirewalls returns the names of all managed firewall rules in a network.
func (c *GCPClient) ListManagedFirewalls(ctx context.Context, projectID, network string) ([]string, error) {
	networkURL := networkSelfLink(projectID, network)
	rules, err := c.firewalls.List(ctx, projectID, networkURL)
	if err != nil {
		return nil, fmt.Errorf("listing firewall rules: %w", err)
	}

	var managed []string
	for _, rule := range rules {
		if rule.Name != nil && strings.HasPrefix(*rule.Name, c.rulePrefix) {
			managed = append(managed, *rule.Name)
		}
	}

	slices.Sort(managed)
	return managed, nil
}

// SyncPolicyWithOptions reconciles firewall rules with optional dry-run behavior.
func (c *GCPClient) SyncPolicyWithOptions(ctx context.Context, p policy.NetworkPolicy, projectID, network string, opts GCPPolicySyncOptions) error {
	safeName := sanitizePolicyName(p.Metadata.Name)
	logging.Infof("Syncing policy '%s' to GCP network %s/%s", safeName, projectID, network)

	networkURL := networkSelfLink(projectID, network)

	var resolveLabels func(policy.PodSelectorSpec) ([]string, error)
	if hasPodSelectors(p) {
		if c.instances == nil {
			return fmt.Errorf("gcp instances client not configured for label resolution")
		}
		resources, err := c.discoverResources(ctx, projectID, networkURL)
		if err != nil {
			return fmt.Errorf("discovering gcp instances: %w", err)
		}

		resolveLabels = func(selector policy.PodSelectorSpec) ([]string, error) {
			return resolveAddresses(resources, selector), nil
		}
	}

	desired, err := c.buildRules(p, networkURL, resolveLabels)
	if err != nil {
		return err
	}

	existing, err := c.firewalls.List(ctx, projectID, networkURL)
	if err != nil {
		return fmt.Errorf("listing firewall rules: %w", err)
	}

	managedExisting := make(map[string]struct{})
	for _, rule := range existing {
		name := rule.GetName()
		if strings.HasPrefix(name, c.rulePrefix) {
			managedExisting[name] = struct{}{}
		}
	}

	if len(desired) > int(maxGCPPriority-c.priorityBase+1) {
		return fmt.Errorf("too many rules (%d) for available priority range", len(desired))
	}

	priority := c.priorityBase
	if opts.DryRun {
		for _, spec := range desired {
			ruleName := c.rulePrefix + spec.name
			logging.Infof("[dry-run] would upsert rule %s with priority %d", ruleName, priority)
			priority++
		}
		for stale := range managedExisting {
			logging.Infof("[dry-run] would delete stale rule %s", stale)
		}
		return nil
	}

	for _, spec := range desired {
		ruleName := c.rulePrefix + spec.name
		spec.rule.Name = new(ruleName)
		spec.rule.Priority = new(priority)

		if _, ok := managedExisting[ruleName]; ok {
			if err := c.firewalls.Patch(ctx, projectID, spec.rule); err != nil {
				return fmt.Errorf("updating rule %s: %w", ruleName, err)
			}
		} else {
			if err := c.firewalls.Insert(ctx, projectID, spec.rule); err != nil {
				return fmt.Errorf("creating rule %s: %w", ruleName, err)
			}
		}
		delete(managedExisting, ruleName)
		priority++
	}

	for stale := range managedExisting {
		if err := c.firewalls.Delete(ctx, projectID, stale); err != nil {
			return fmt.Errorf("deleting stale rule %s: %w", stale, err)
		}
	}

	return nil
}

type gcpRuleSpec struct {
	name    string
	sortKey string
	rule    *computepb.Firewall
}

func (c *GCPClient) buildRules(p policy.NetworkPolicy, networkURL string, resolveLabels func(policy.PodSelectorSpec) ([]string, error)) ([]gcpRuleSpec, error) {
	var rules []gcpRuleSpec

	for _, egress := range p.Spec.Egress {
		cidr := strings.TrimSpace(egress.To.IPBlock.CIDR)
		selector := egress.To.PodSelector
		if len(egress.To.NamespaceSelector.MatchLabels) > 0 || len(egress.To.NamespaceSelector.MatchExpressions) > 0 {
			return nil, fmt.Errorf("namespaceSelector is not supported for gcp firewall rules")
		}

		if cidr == "" && len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
			continue
		}

		for _, port := range egress.Ports {
			if port.PortName != "" {
				return nil, fmt.Errorf("named ports are not supported for gcp firewall rules")
			}
			start := port.Port
			end := port.Port
			if port.EndPort != nil {
				end = *port.EndPort
			}
			if err := validatePortRange(start, end); err != nil {
				return nil, err
			}
			protoValue, err := normalizeGCPProtocol(port.Protocol)
			if err != nil {
				return nil, err
			}

			destRanges, nameSuffix, sortSuffix, err := c.resolveTargetCIDRs(resolveLabels, cidr, selector)
			if err != nil {
				return nil, err
			}

			portLabel := portRangeLabel(start, end)
			rules = append(rules, gcpRuleSpec{
				name:    sanitizeGCPRuleName(fmt.Sprintf("egress-%s-%s-%s", protoValue, portLabel, nameSuffix)),
				sortKey: fmt.Sprintf("egress-%s-%s-%s", protoValue, portLabel, sortSuffix),
				rule: &computepb.Firewall{
					Network:           new(networkURL),
					Direction:         new("EGRESS"),
					DestinationRanges: destRanges,
					Allowed: []*computepb.Allowed{{
						IPProtocol: new(protoValue),
						Ports:      []string{portRange(start, end)},
					}},
					Disabled:    new(false),
					Description: new(gcpRuleDescription),
				},
			})
		}
	}

	for _, ingress := range p.Spec.Ingress {
		cidr := strings.TrimSpace(ingress.From.IPBlock.CIDR)
		selector := ingress.From.PodSelector
		if len(ingress.From.NamespaceSelector.MatchLabels) > 0 || len(ingress.From.NamespaceSelector.MatchExpressions) > 0 {
			return nil, fmt.Errorf("namespaceSelector is not supported for gcp firewall rules")
		}

		if cidr == "" && len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
			continue
		}

		for _, port := range ingress.Ports {
			if port.PortName != "" {
				return nil, fmt.Errorf("named ports are not supported for gcp firewall rules")
			}
			start := port.Port
			end := port.Port
			if port.EndPort != nil {
				end = *port.EndPort
			}
			if err := validatePortRange(start, end); err != nil {
				return nil, err
			}
			protoValue, err := normalizeGCPProtocol(port.Protocol)
			if err != nil {
				return nil, err
			}

			sourceRanges, nameSuffix, sortSuffix, err := c.resolveTargetCIDRs(resolveLabels, cidr, selector)
			if err != nil {
				return nil, err
			}

			portLabel := portRangeLabel(start, end)
			rules = append(rules, gcpRuleSpec{
				name:    sanitizeGCPRuleName(fmt.Sprintf("ingress-%s-%s-%s", protoValue, portLabel, nameSuffix)),
				sortKey: fmt.Sprintf("ingress-%s-%s-%s", protoValue, portLabel, sortSuffix),
				rule: &computepb.Firewall{
					Network:      new(networkURL),
					Direction:    new("INGRESS"),
					SourceRanges: sourceRanges,
					Allowed: []*computepb.Allowed{{
						IPProtocol: new(protoValue),
						Ports:      []string{portRange(start, end)},
					}},
					Disabled:    new(false),
					Description: new(gcpRuleDescription),
				},
			})
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].sortKey < rules[j].sortKey
	})

	return rules, nil
}

func normalizeGCPProtocol(protoValue string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(protoValue))
	switch p {
	case "tcp", "udp":
		return p, nil
	default:
		return "", fmt.Errorf("unsupported protocol %s for gcp firewall rules", protoValue)
	}
}

func validatePortRange(start int, end int) error {
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

func sanitizeGCPRuleName(name string) string {
	var b strings.Builder
	b.Grow(len(name))

	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('-')
	}

	cleaned := strings.Trim(b.String(), "-")
	if cleaned == "" {
		return "rule"
	}
	return cleaned
}

func portRange(start int, end int) string {
	if end <= start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func portRangeLabel(start int, end int) string {
	if end <= start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func networkSelfLink(projectID, network string) string {
	return fmt.Sprintf("projects/%s/global/networks/%s", projectID, network)
}

func (c *GCPClient) resolveTargetCIDRs(resolveLabels func(policy.PodSelectorSpec) ([]string, error), cidr string, selector policy.PodSelectorSpec) ([]string, string, string, error) {
	if cidr != "" {
		return []string{cidr}, compactCIDR(cidr), cidr, nil
	}

	if resolveLabels == nil {
		return nil, "selector-missing-discovery", "selector-missing-discovery", fmt.Errorf("podSelector requires service discovery")
	}

	ips, err := resolveLabels(selector)
	if err != nil {
		return nil, "selector-resolution", "selector-resolution", err
	}
	if len(ips) == 0 {
		return nil, "selector-no-targets", "selector-no-targets", fmt.Errorf("podSelector %v resolved to no addresses", selector)
	}

	cidrs, err := ipsToCIDRs(ips)
	if err != nil {
		return nil, "selector-invalid-targets", "selector-invalid-targets", err
	}

	labelKey := selectorKey(selector)
	return cidrs, fmt.Sprintf("sel-%s", labelKey), fmt.Sprintf("sel-%s", labelKey), nil
}

func selectorKey(selector policy.PodSelectorSpec) string {
	key := policy.SelectorKeySpec(selector)
	if strings.TrimSpace(key) == "" {
		return "any"
	}
	return sanitizeGCPRuleName(key)
}

func ipsToCIDRs(ips []string) ([]string, error) {
	uniq := make(map[string]struct{})
	for _, ip := range ips {
		ipStr := strings.TrimSpace(ip)
		if ipStr == "" {
			continue
		}
		cidr, err := ipToCIDR(ipStr)
		if err != nil {
			return nil, err
		}
		uniq[cidr] = struct{}{}
	}

	cidrs := make([]string, 0, len(uniq))
	for cidr := range uniq {
		cidrs = append(cidrs, cidr)
	}
	slices.Sort(cidrs)
	return cidrs, nil
}

func ipToCIDR(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid ip %s", ip)
	}
	if parsed.To4() != nil {
		return fmt.Sprintf("%s/32", parsed.String()), nil
	}
	return fmt.Sprintf("%s/128", parsed.String()), nil
}

func hasPodSelectors(p policy.NetworkPolicy) bool {
	for _, e := range p.Spec.Egress {
		if len(e.To.PodSelector.MatchLabels) > 0 || len(e.To.PodSelector.MatchExpressions) > 0 {
			return true
		}
	}
	for _, in := range p.Spec.Ingress {
		if len(in.From.PodSelector.MatchLabels) > 0 || len(in.From.PodSelector.MatchExpressions) > 0 {
			return true
		}
	}
	return false
}

func (c *GCPClient) discoverResources(ctx context.Context, projectID, networkURL string) ([]Resource, error) {
	instances, err := c.instances.AggregatedList(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing instances: %w", err)
	}

	var resources []Resource
	for _, inst := range instances {
		if inst == nil {
			continue
		}

		labels := make(map[string]string, len(inst.Labels))
		maps.Copy(labels, inst.Labels)

		for _, nic := range inst.NetworkInterfaces {
			if nic == nil {
				continue
			}
			if nic.Network == nil || *nic.Network != networkURL {
				continue
			}

			privateIP := nic.GetNetworkIP()
			publicIP := ""
			if len(nic.AccessConfigs) > 0 {
				publicIP = nic.AccessConfigs[0].GetNatIP()
			}

			resources = append(resources, Resource{
				ID:        fmt.Sprintf("%d", inst.GetId()),
				Name:      inst.GetName(),
				Type:      "GCE",
				PrivateIP: privateIP,
				PublicIP:  publicIP,
				Labels:    labels,
			})
		}
	}

	return resources, nil
}

func resolveAddresses(resources []Resource, selector policy.PodSelectorSpec) []string {
	var addrs []string
	for _, r := range resources {
		if policy.MatchesSelector(r.Labels, selector) {
			if r.PrivateIP != "" {
				addrs = append(addrs, r.PrivateIP)
			}
			if r.PublicIP != "" {
				addrs = append(addrs, r.PublicIP)
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
	slices.Sort(dedup)
	return dedup
}
