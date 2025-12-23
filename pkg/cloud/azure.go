package cloud

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

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

type azureRulesClient struct {
	client *armnetwork.SecurityRulesClient
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

// AzureClient manages Azure NSG synchronization.
type AzureClient struct {
	rules        securityRulesClient
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
	log.Printf("Syncing policy '%s' to NSG %s/%s", safeName, resourceGroup, nsgName)

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

	for idx, spec := range desired {
		priority := c.priorityBase + int32(idx)
		ruleName := c.rulePrefix + spec.name

		spec.rule.Name = &ruleName
		spec.rule.Properties.Priority = &priority

		if err := c.rules.Upsert(ctx, resourceGroup, nsgName, ruleName, spec.rule); err != nil {
			return fmt.Errorf("upserting rule %s: %w", ruleName, err)
		}
		delete(managedExisting, ruleName)
	}

	for stale := range managedExisting {
		if err := c.rules.Delete(ctx, resourceGroup, nsgName, stale); err != nil {
			return fmt.Errorf("deleting stale rule %s: %w", stale, err)
		}
	}

	return nil
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
			if err := validatePort(port.Port); err != nil {
				return nil, err
			}

			proto := normalizeProtocol(port.Protocol)
			rules = append(rules, ruleSpec{
				name:    sanitizeRuleName(fmt.Sprintf("egress-%s-%d-%s", proto, port.Port, compactCIDR(cidr))),
				sortKey: fmt.Sprintf("egress-%s-%05d-%s", proto, port.Port, cidr),
				rule: armnetwork.SecurityRule{
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Access:                   ptrAccess(armnetwork.SecurityRuleAccessAllow),
						Direction:                ptrDirection(armnetwork.SecurityRuleDirectionOutbound),
						Protocol:                 ptrProtocol(proto),
						SourceAddressPrefix:      ptrString(azureProtocolAsterisk),
						DestinationAddressPrefix: ptrString(cidr),
						SourcePortRange:          ptrString(azureProtocolAsterisk),
						DestinationPortRange:     ptrString(portRange(port.Port)),
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
			if err := validatePort(port.Port); err != nil {
				return nil, err
			}

			proto := normalizeProtocol(port.Protocol)
			rules = append(rules, ruleSpec{
				name:    sanitizeRuleName(fmt.Sprintf("ingress-%s-%d-%s", proto, port.Port, compactCIDR(cidr))),
				sortKey: fmt.Sprintf("ingress-%s-%05d-%s", proto, port.Port, cidr),
				rule: armnetwork.SecurityRule{
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Access:                   ptrAccess(armnetwork.SecurityRuleAccessAllow),
						Direction:                ptrDirection(armnetwork.SecurityRuleDirectionInbound),
						Protocol:                 ptrProtocol(proto),
						SourceAddressPrefix:      ptrString(cidr),
						DestinationAddressPrefix: ptrString(azureProtocolAsterisk),
						SourcePortRange:          ptrString(azureProtocolAsterisk),
						DestinationPortRange:     ptrString(portRange(port.Port)),
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

func validatePort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
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

func portRange(port int) string {
	return fmt.Sprintf("%d", port)
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
