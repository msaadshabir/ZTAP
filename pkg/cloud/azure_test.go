package cloud

import (
	"context"
	"testing"

	"ztap/pkg/policy"

	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
)

type mockSecurityRulesClient struct {
	listRules []*armnetwork.SecurityRule
	listErr   error

	upserts   []armnetwork.SecurityRule
	upsertErr error

	deletes   []string
	deleteErr error
}

type mockAzureInterfaces struct {
	items []*armnetwork.Interface
	all   []*armnetwork.Interface
	err   error
}

func (m *mockAzureInterfaces) List(ctx context.Context, resourceGroup string) ([]*armnetwork.Interface, error) {
	return m.items, m.err
}

func (m *mockAzureInterfaces) ListAll(ctx context.Context) ([]*armnetwork.Interface, error) {
	return m.all, m.err
}

type mockAzurePublicIPs struct {
	items []*armnetwork.PublicIPAddress
	all   []*armnetwork.PublicIPAddress
	err   error
}

func (m *mockAzurePublicIPs) List(ctx context.Context, resourceGroup string) ([]*armnetwork.PublicIPAddress, error) {
	return m.items, m.err
}

func (m *mockAzurePublicIPs) ListAll(ctx context.Context) ([]*armnetwork.PublicIPAddress, error) {
	return m.all, m.err
}

func (m *mockSecurityRulesClient) List(ctx context.Context, resourceGroup, nsgName string) ([]*armnetwork.SecurityRule, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listRules, nil
}

func (m *mockSecurityRulesClient) Upsert(ctx context.Context, resourceGroup, nsgName, ruleName string, rule armnetwork.SecurityRule) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.upserts = append(m.upserts, rule)
	return nil
}

func (m *mockSecurityRulesClient) Delete(ctx context.Context, resourceGroup, nsgName, ruleName string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletes = append(m.deletes, ruleName)
	return nil
}

func TestAzureSyncPolicyReconcilesRules(t *testing.T) {
	mock := &mockSecurityRulesClient{
		listRules: []*armnetwork.SecurityRule{
			{Name: new("ztap-stale-rule")},
		},
	}

	client := &AzureClient{
		rules:        mock,
		rulePrefix:   defaultAzureRulePrefix,
		priorityBase: defaultPriorityBase,
	}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "web-to-db"},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []policy.EgressRule{
				{
					To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
					Ports: []policy.PortSpec{{Protocol: "TCP", Port: 5432}},
				},
			},
			Ingress: []policy.IngressRule{
				{
					From:  policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "10.1.0.0/16"}},
					Ports: []policy.PortSpec{{Protocol: "UDP", Port: 53}},
				},
			},
		},
	}

	err := client.SyncPolicy(t.Context(), np, "rg", "nsg")
	if err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(mock.upserts) != 2 {
		t.Fatalf("expected 2 upserts, got %d", len(mock.upserts))
	}

	outbound := mock.upserts[0]
	if outbound.Properties == nil || outbound.Properties.Direction == nil {
		t.Fatalf("missing outbound properties")
	}
	if *outbound.Properties.Direction != armnetwork.SecurityRuleDirectionOutbound {
		t.Fatalf("expected outbound rule")
	}
	if outbound.Properties.DestinationAddressPrefix == nil || *outbound.Properties.DestinationAddressPrefix != "10.0.0.0/24" {
		t.Fatalf("unexpected destination: %#v", outbound.Properties.DestinationAddressPrefix)
	}
	if outbound.Properties.DestinationPortRange == nil || *outbound.Properties.DestinationPortRange != "5432" {
		t.Fatalf("unexpected destination port: %#v", outbound.Properties.DestinationPortRange)
	}
	if outbound.Properties.Protocol == nil || *outbound.Properties.Protocol != armnetwork.SecurityRuleProtocolTCP {
		t.Fatalf("unexpected protocol: %#v", outbound.Properties.Protocol)
	}
	if outbound.Properties.Priority == nil || *outbound.Properties.Priority != defaultPriorityBase {
		t.Fatalf("unexpected priority: %#v", outbound.Properties.Priority)
	}

	inbound := mock.upserts[1]
	if inbound.Properties == nil || inbound.Properties.Direction == nil {
		t.Fatalf("missing inbound properties")
	}
	if *inbound.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
		t.Fatalf("expected inbound rule")
	}
	if inbound.Properties.SourceAddressPrefix == nil || *inbound.Properties.SourceAddressPrefix != "10.1.0.0/16" {
		t.Fatalf("unexpected source: %#v", inbound.Properties.SourceAddressPrefix)
	}
	if inbound.Properties.DestinationPortRange == nil || *inbound.Properties.DestinationPortRange != "53" {
		t.Fatalf("unexpected port: %#v", inbound.Properties.DestinationPortRange)
	}
	if inbound.Properties.Priority == nil || *inbound.Properties.Priority != defaultPriorityBase+1 {
		t.Fatalf("unexpected priority for inbound: %#v", inbound.Properties.Priority)
	}

	if len(mock.deletes) != 1 || mock.deletes[0] != "ztap-stale-rule" {
		t.Fatalf("expected stale rule deletion, got %#v", mock.deletes)
	}
}

func TestAzureSyncPolicyInvalidPort(t *testing.T) {
	mock := &mockSecurityRulesClient{}
	client := &AzureClient{rules: mock, rulePrefix: defaultAzureRulePrefix, priorityBase: defaultPriorityBase}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "bad"},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 70000}},
			}},
		},
	}

	if err := client.SyncPolicy(t.Context(), np, "rg", "nsg"); err == nil {
		t.Fatal("expected error for invalid port")
	}
	if len(mock.upserts) != 0 {
		t.Fatalf("expected no upserts, got %d", len(mock.upserts))
	}
}

func TestAzureSyncPolicyPortRange(t *testing.T) {
	end := 8080
	mock := &mockSecurityRulesClient{}
	client := &AzureClient{rules: mock, rulePrefix: defaultAzureRulePrefix, priorityBase: defaultPriorityBase}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "range"},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 8000, EndPort: &end}},
			}},
		},
	}

	if err := client.SyncPolicy(t.Context(), np, "rg", "nsg"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}
	if len(mock.upserts) != 1 {
		t.Fatalf("expected 1 upsert, got %d", len(mock.upserts))
	}
	rule := mock.upserts[0]
	if rule.Properties == nil || rule.Properties.DestinationPortRange == nil {
		t.Fatalf("expected destination port range")
	}
	if *rule.Properties.DestinationPortRange != "8000-8080" {
		t.Fatalf("unexpected port range: %s", *rule.Properties.DestinationPortRange)
	}
}

func TestAzureDiscoverResources(t *testing.T) {
	privateIP := "10.0.0.5"
	publicIPID := "/subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip1"
	publicIP := "203.0.113.5"

	interfaces := &mockAzureInterfaces{items: []*armnetwork.Interface{
		{
			ID:   new("/subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"),
			Name: new("nic1"),
			Tags: map[string]*string{"app": new("web")},
			Properties: &armnetwork.InterfacePropertiesFormat{
				IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
					{
						Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
							PrivateIPAddress: new(privateIP),
							PublicIPAddress:  &armnetwork.PublicIPAddress{ID: new(publicIPID)},
						},
					},
				},
			},
		},
	}}

	publicIPs := &mockAzurePublicIPs{items: []*armnetwork.PublicIPAddress{
		{
			ID: new(publicIPID),
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{
				IPAddress: new(publicIP),
			},
		},
	}}

	client := &AzureClient{interfaces: interfaces, publicIPs: publicIPs, rulePrefix: defaultAzureRulePrefix, priorityBase: defaultPriorityBase}
	resources, err := client.DiscoverResources(t.Context(), "rg")
	if err != nil {
		t.Fatalf("DiscoverResources returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].PrivateIP != privateIP {
		t.Fatalf("unexpected private IP: %s", resources[0].PrivateIP)
	}
	if resources[0].PublicIP != publicIP {
		t.Fatalf("unexpected public IP: %s", resources[0].PublicIP)
	}
}
