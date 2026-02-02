package cloud

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"ztap/pkg/logging"
	"ztap/pkg/policy"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
)

const (
	defaultAzureRulePrefix = "ztap-"
	defaultPriorityBase    = int32(2000)
	maxAzurePriority       = int32(4096)
	azureProtocolAsterisk  = "*"
	managedRuleDescription = "Managed by ZTAP"
)

type securityRulesClient interface {
	List(ctx context.Context, resourceGroup, nsgName string) ([]*armnetwork.SecurityRule, error)
	Upsert(ctx context.Context, resourceGroup, nsgName, ruleName string, rule armnetwork.SecurityRule) error
	Delete(ctx context.Context, resourceGroup, nsgName, ruleName string) error
}

type azureInterfacesClient interface {
	List(ctx context.Context, resourceGroup string) ([]*armnetwork.Interface, error)
	ListAll(ctx context.Context) ([]*armnetwork.Interface, error)
}

type azurePublicIPsClient interface {
	List(ctx context.Context, resourceGroup string) ([]*armnetwork.PublicIPAddress, error)
	ListAll(ctx context.Context) ([]*armnetwork.PublicIPAddress, error)
}

type azureRulesClient struct {
	client *armnetwork.SecurityRulesClient
}

type azureInterfacesClientImpl struct {
	client *armnetwork.InterfacesClient
}

type azurePublicIPsClientImpl struct {
	client *armnetwork.PublicIPAddressesClient
}

func (c *azureRulesClient) List(ctx context.Context, resourceGroup, nsgName string) ([]*armnetwork.SecurityRule, error) {
	pager := c.client.NewListPager(resourceGroup, nsgName, nil)
	var rules []*armnetwork.SecurityRule

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page.Value...)
	}

	return rules, nil
}

func (c *azureRulesClient) Upsert(ctx context.Context, resourceGroup, nsgName, ruleName string, rule armnetwork.SecurityRule) error {
	poller, err := c.client.BeginCreateOrUpdate(ctx, resourceGroup, nsgName, ruleName, rule, nil)
	if err != nil {
		return err
	}

	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

func (c *azureRulesClient) Delete(ctx context.Context, resourceGroup, nsgName, ruleName string) error {
	poller, err := c.client.BeginDelete(ctx, resourceGroup, nsgName, ruleName, nil)
	if err != nil {
		return err
	}

	_, err = poller.PollUntilDone(ctx, nil)
	return err
}

func (c *azureInterfacesClientImpl) List(ctx context.Context, resourceGroup string) ([]*armnetwork.Interface, error) {
	pager := c.client.NewListPager(resourceGroup, nil)
	var out []*armnetwork.Interface
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (c *azureInterfacesClientImpl) ListAll(ctx context.Context) ([]*armnetwork.Interface, error) {
	pager := c.client.NewListAllPager(nil)
	var out []*armnetwork.Interface
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (c *azurePublicIPsClientImpl) List(ctx context.Context, resourceGroup string) ([]*armnetwork.PublicIPAddress, error) {
	pager := c.client.NewListPager(resourceGroup, nil)
	var out []*armnetwork.PublicIPAddress
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (c *azurePublicIPsClientImpl) ListAll(ctx context.Context) ([]*armnetwork.PublicIPAddress, error) {
	pager := c.client.NewListAllPager(nil)
	var out []*armnetwork.PublicIPAddress
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// AzureClient manages Azure NSG synchronization.
type AzureClient struct {
	rules        securityRulesClient
	interfaces   azureInterfacesClient
	publicIPs    azurePublicIPsClient
	rulePrefix   string
	priorityBase int32
}

// NewAzureClient creates a new Azure client using default credentials.
func NewAzureClient(ctx context.Context, subscriptionID string) (*AzureClient, error) {
	return NewAzureClientWithOptions(ctx, subscriptionID, AzureOptions{})
}

// AzureOptions customizes Azure client behavior.
type AzureOptions struct {
	RulePrefix   string
	PriorityBase int32
}

// NewAzureClientWithOptions creates a new Azure client with optional overrides.
func NewAzureClientWithOptions(ctx context.Context, subscriptionID string, opts AzureOptions) (*AzureClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize azure credential: %w", err)
	}

	rulesClient, err := armnetwork.NewSecurityRulesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create security rules client: %w", err)
	}

	client := &AzureClient{
		rules:        &azureRulesClient{client: rulesClient},
		rulePrefix:   defaultAzureRulePrefix,
		priorityBase: defaultPriorityBase,
	}

	interfacesClient, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create interfaces client: %w", err)
	}
	publicIPsClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create public IPs client: %w", err)
	}
	client.interfaces = &azureInterfacesClientImpl{client: interfacesClient}
	client.publicIPs = &azurePublicIPsClientImpl{client: publicIPsClient}

	if strings.TrimSpace(opts.RulePrefix) != "" {
		client.rulePrefix = strings.TrimSpace(opts.RulePrefix)
	}
	if opts.PriorityBase > 0 {
		client.priorityBase = opts.PriorityBase
	}

	return client, nil
}

// SyncPolicy converts a ZTAP policy into NSG security rules and reconciles them on the target NSG.
func (c *AzureClient) SyncPolicy(ctx context.Context, p policy.NetworkPolicy, resourceGroup, nsgName string) error {
	safeName := sanitizePolicyName(p.Metadata.Name)
	logging.Infof("Syncing policy '%s' to NSG %s/%s", safeName, resourceGroup, nsgName)

	desired, err := c.buildRules(p)
	if err != nil {
		return err
	}

	existing, err := c.rules.List(ctx, resourceGroup, nsgName)
	if err != nil {
		return fmt.Errorf("listing NSG rules: %w", err)
	}

	managedExisting := make(map[string]struct{})
	for _, rule := range existing {
		if rule.Name == nil {
			continue
		}
		if strings.HasPrefix(*rule.Name, c.rulePrefix) {
			managedExisting[*rule.Name] = struct{}{}
		}
	}

	if len(desired) > int(maxAzurePriority-c.priorityBase) {
		return fmt.Errorf("too many rules (%d) for available priority range", len(desired))
	}

	priority := c.priorityBase
	for _, spec := range desired {
		rulePriority := priority
		ruleName := c.rulePrefix + spec.name

		spec.rule.Name = &ruleName
		spec.rule.Properties.Priority = &rulePriority

		if err := c.rules.Upsert(ctx, resourceGroup, nsgName, ruleName, spec.rule); err != nil {
			return fmt.Errorf("upserting rule %s: %w", ruleName, err)
		}
		delete(managedExisting, ruleName)
		priority++
	}

	for stale := range managedExisting {
		if err := c.rules.Delete(ctx, resourceGroup, nsgName, stale); err != nil {
			return fmt.Errorf("deleting stale rule %s: %w", stale, err)
		}
	}

	return nil
}

// DiscoverResources lists Azure network interfaces and associated IPs.
func (c *AzureClient) DiscoverResources(ctx context.Context, resourceGroup string) ([]Resource, error) {
	if c.interfaces == nil {
		return nil, fmt.Errorf("azure interfaces client not configured for discovery")
	}

	var nics []*armnetwork.Interface
	var err error
	if strings.TrimSpace(resourceGroup) == "" {
		nics, err = c.interfaces.ListAll(ctx)
	} else {
		nics, err = c.interfaces.List(ctx, resourceGroup)
	}
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	publicByID, err := c.listPublicIPs(ctx, resourceGroup)
	if err != nil {
		return nil, err
	}

	resources := make([]Resource, 0)
	for _, nic := range nics {
		if nic == nil || nic.Properties == nil {
			continue
		}
		labels := map[string]string{}
		if nic.Tags != nil {
			labels = make(map[string]string, len(nic.Tags))
			for k, v := range nic.Tags {
				if v == nil {
					continue
				}
				labels[k] = *v
			}
		}
		name := ""
		if nic.Name != nil {
			name = *nic.Name
		}
		id := ""
		if nic.ID != nil {
			id = *nic.ID
		}

		for _, ipcfg := range nic.Properties.IPConfigurations {
			if ipcfg == nil || ipcfg.Properties == nil {
				continue
			}
			privateIP := ""
			if ipcfg.Properties.PrivateIPAddress != nil {
				privateIP = *ipcfg.Properties.PrivateIPAddress
			}
			publicIP := ""
			if ipcfg.Properties.PublicIPAddress != nil && ipcfg.Properties.PublicIPAddress.ID != nil {
				if mapped, ok := publicByID[*ipcfg.Properties.PublicIPAddress.ID]; ok {
					publicIP = mapped
				}
			}

			resources = append(resources, Resource{
				ID:        id,
				Name:      name,
				Type:      "NIC",
				PrivateIP: privateIP,
				PublicIP:  publicIP,
				Labels:    labels,
			})
		}
	}

	return resources, nil
}

func (c *AzureClient) listPublicIPs(ctx context.Context, resourceGroup string) (map[string]string, error) {
	if c.publicIPs == nil {
		return map[string]string{}, nil
	}

	var pips []*armnetwork.PublicIPAddress
	var err error
	if strings.TrimSpace(resourceGroup) == "" {
		pips, err = c.publicIPs.ListAll(ctx)
	} else {
		pips, err = c.publicIPs.List(ctx, resourceGroup)
	}
	if err != nil {
		return nil, fmt.Errorf("listing public IPs: %w", err)
	}

	lookup := make(map[string]string, len(pips))
	for _, pip := range pips {
		if pip == nil || pip.ID == nil || pip.Properties == nil || pip.Properties.IPAddress == nil {
			continue
		}
		lookup[*pip.ID] = *pip.Properties.IPAddress
	}
	return lookup, nil
}

type ruleSpec struct {
	name    string
	sortKey string
	rule    armnetwork.SecurityRule
}

func (c *AzureClient) buildRules(p policy.NetworkPolicy) ([]ruleSpec, error) {
	var rules []ruleSpec

	for _, egress := range p.Spec.Egress {
		cidr := strings.TrimSpace(egress.To.IPBlock.CIDR)
		if cidr == "" {
			continue
		}

		for _, port := range egress.Ports {
			if port.PortName != "" {
				return nil, fmt.Errorf("named ports are not supported for Azure NSG rules")
			}
			start := port.Port
			end := port.Port
			if port.EndPort != nil {
				end = *port.EndPort
			}
			if err := validateAzurePortRange(start, end); err != nil {
				return nil, err
			}

			proto := normalizeProtocol(port.Protocol)
			portLabel := azurePortRangeLabel(start, end)
			rules = append(rules, ruleSpec{
				name:    sanitizeRuleName(fmt.Sprintf("egress-%s-%s-%s", proto, portLabel, compactCIDR(cidr))),
				sortKey: fmt.Sprintf("egress-%s-%s-%s", proto, portLabel, cidr),
				rule: armnetwork.SecurityRule{
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Access:                   ptrAccess(armnetwork.SecurityRuleAccessAllow),
						Direction:                ptrDirection(armnetwork.SecurityRuleDirectionOutbound),
						Protocol:                 ptrProtocol(proto),
						SourceAddressPrefix:      ptrString(azureProtocolAsterisk),
						DestinationAddressPrefix: ptrString(cidr),
						SourcePortRange:          ptrString(azureProtocolAsterisk),
						DestinationPortRange:     ptrString(azurePortRange(start, end)),
						Description:              ptrString(managedRuleDescription),
					},
				},
			})
		}
	}

	for _, ingress := range p.Spec.Ingress {
		cidr := strings.TrimSpace(ingress.From.IPBlock.CIDR)
		if cidr == "" {
			continue
		}

		for _, port := range ingress.Ports {
			if port.PortName != "" {
				return nil, fmt.Errorf("named ports are not supported for Azure NSG rules")
			}
			start := port.Port
			end := port.Port
			if port.EndPort != nil {
				end = *port.EndPort
			}
			if err := validateAzurePortRange(start, end); err != nil {
				return nil, err
			}

			proto := normalizeProtocol(port.Protocol)
			portLabel := azurePortRangeLabel(start, end)
			rules = append(rules, ruleSpec{
				name:    sanitizeRuleName(fmt.Sprintf("ingress-%s-%s-%s", proto, portLabel, compactCIDR(cidr))),
				sortKey: fmt.Sprintf("ingress-%s-%s-%s", proto, portLabel, cidr),
				rule: armnetwork.SecurityRule{
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Access:                   ptrAccess(armnetwork.SecurityRuleAccessAllow),
						Direction:                ptrDirection(armnetwork.SecurityRuleDirectionInbound),
						Protocol:                 ptrProtocol(proto),
						SourceAddressPrefix:      ptrString(cidr),
						DestinationAddressPrefix: ptrString(azureProtocolAsterisk),
						SourcePortRange:          ptrString(azureProtocolAsterisk),
						DestinationPortRange:     ptrString(azurePortRange(start, end)),
						Description:              ptrString(managedRuleDescription),
					},
				},
			})
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].sortKey < rules[j].sortKey
	})

	return rules, nil
}

func validateAzurePortRange(start int, end int) error {
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

func sanitizePolicyName(name string) string {
	safe := strings.ReplaceAll(name, "\n", "")
	safe = strings.ReplaceAll(safe, "\r", "")
	return strings.TrimSpace(safe)
}

func sanitizeRuleName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
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

func normalizeProtocol(proto string) string {
	if proto == "" {
		return azureProtocolAsterisk
	}
	p := strings.ToUpper(proto)
	switch p {
	case "TCP", "UDP", "ICMP":
		return p
	default:
		return azureProtocolAsterisk
	}
}

func azurePortRange(start int, end int) string {
	if end <= start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func azurePortRangeLabel(start int, end int) string {
	if end <= start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func compactCIDR(cidr string) string {
	r := strings.NewReplacer("/", "-", ":", "-", " ", "-")
	return r.Replace(cidr)
}

func ptrString(v string) *string { return &v }
func ptrProtocol(proto string) *armnetwork.SecurityRuleProtocol {
	switch strings.ToUpper(proto) {
	case "TCP":
		p := armnetwork.SecurityRuleProtocolTCP
		return &p
	case "UDP":
		p := armnetwork.SecurityRuleProtocolUDP
		return &p
	case "ICMP":
		p := armnetwork.SecurityRuleProtocolIcmp
		return &p
	default:
		p := armnetwork.SecurityRuleProtocolAsterisk
		return &p
	}
}

func ptrAccess(a armnetwork.SecurityRuleAccess) *armnetwork.SecurityRuleAccess          { return &a }
func ptrDirection(d armnetwork.SecurityRuleDirection) *armnetwork.SecurityRuleDirection { return &d }
