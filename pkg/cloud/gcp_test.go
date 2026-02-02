package cloud

import (
	"context"
	"strings"
	"testing"

	"ztap/pkg/policy"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

type mockFirewalls struct {
	listRules   []*computepb.Firewall
	listErr     error
	insertErr   error
	patchErr    error
	deleteErr   error
	inserts     []*computepb.Firewall
	patches     []*computepb.Firewall
	deletes     []string
	lastProject string
	lastNetwork string
}

type mockInstances struct {
	instances []*computepb.Instance
	err       error
}

func (m *mockInstances) AggregatedList(ctx context.Context, projectID string) ([]*computepb.Instance, error) {
	return m.instances, m.err
}

func (m *mockFirewalls) List(ctx context.Context, projectID, networkURL string) ([]*computepb.Firewall, error) {
	m.lastProject = projectID
	m.lastNetwork = networkURL
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listRules, nil
}

func (m *mockFirewalls) Insert(ctx context.Context, projectID string, rule *computepb.Firewall) error {
	m.lastProject = projectID
	m.inserts = append(m.inserts, proto.Clone(rule).(*computepb.Firewall))
	return m.insertErr
}

func (m *mockFirewalls) Patch(ctx context.Context, projectID string, rule *computepb.Firewall) error {
	m.lastProject = projectID
	m.patches = append(m.patches, proto.Clone(rule).(*computepb.Firewall))
	return m.patchErr
}

func (m *mockFirewalls) Delete(ctx context.Context, projectID, name string) error {
	m.lastProject = projectID
	m.deletes = append(m.deletes, name)
	return m.deleteErr
}

func TestGCPSyncPolicyReconcilesRules(t *testing.T) {
	networkURL := networkSelfLink("demo", "default")
	mock := &mockFirewalls{
		listRules: []*computepb.Firewall{
			{Name: proto.String("ztap-egress-tcp-5432-10-0-0-0-24")},
			{Name: proto.String("ztap-stale-rule")},
		},
	}

	client := &GCPClient{
		firewalls:    mock,
		rulePrefix:   defaultGCPRulePrefix,
		priorityBase: defaultGCPPriorityBase,
	}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "web-to-db"},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []policy.EgressRule{
				{To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
					Ports: []policy.PortSpec{{Protocol: "TCP", Port: 5432}}},
			},
			Ingress: []policy.IngressRule{
				{From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "10.1.0.0/16"}},
					Ports: []policy.PortSpec{{Protocol: "UDP", Port: 53}}},
			},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "demo", "default"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if mock.lastProject != "demo" || mock.lastNetwork != networkURL {
		t.Fatalf("unexpected project/network: %s %s", mock.lastProject, mock.lastNetwork)
	}

	if len(mock.patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(mock.patches))
	}
	patched := mock.patches[0]
	if patched.GetName() != "ztap-egress-tcp-5432-10-0-0-0-24" {
		t.Fatalf("unexpected patched rule name: %s", patched.GetName())
	}
	if patched.GetDirection() != "EGRESS" || len(patched.GetDestinationRanges()) != 1 || patched.GetDestinationRanges()[0] != "10.0.0.0/24" {
		t.Fatalf("unexpected patched rule contents: %#v", patched)
	}
	if patched.Priority == nil {
		t.Fatalf("expected patched rule priority to be set")
	}

	if len(mock.inserts) != 1 {
		t.Fatalf("expected 1 insert, got %d", len(mock.inserts))
	}
	inserted := mock.inserts[0]
	if inserted.GetDirection() != "INGRESS" || len(inserted.GetSourceRanges()) != 1 || inserted.GetSourceRanges()[0] != "10.1.0.0/16" {
		t.Fatalf("unexpected inserted rule contents: %#v", inserted)
	}
	if inserted.Priority == nil {
		t.Fatalf("expected inserted rule priority to be set")
	}
	if inserted.Priority != nil && patched.Priority != nil && *inserted.Priority <= *patched.Priority {
		t.Fatalf("expected ingress priority to be higher than patched rule")
	}

	if len(mock.deletes) != 1 || mock.deletes[0] != "ztap-stale-rule" {
		t.Fatalf("expected stale rule deletion, got %#v", mock.deletes)
	}
}

func TestGCPSyncPolicyUnsupportedProtocol(t *testing.T) {
	mock := &mockFirewalls{}
	client := &GCPClient{firewalls: mock, rulePrefix: defaultGCPRulePrefix, priorityBase: defaultGCPPriorityBase}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "icmp"},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Ingress: []policy.IngressRule{
				{From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
					Ports: []policy.PortSpec{{Protocol: "ICMP", Port: 8}}},
			},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "demo", "default"); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
	if len(mock.inserts) != 0 || len(mock.patches) != 0 || len(mock.deletes) != 0 {
		t.Fatalf("expected no operations on error")
	}
}

func TestGCPSyncPolicyWithPodSelector(t *testing.T) {
	projectID := "demo"
	network := "default"
	networkURL := networkSelfLink(projectID, network)

	fw := &mockFirewalls{}
	instances := &mockInstances{
		instances: []*computepb.Instance{
			{
				Name:   proto.String("vm1"),
				Id:     proto.Uint64(1),
				Labels: map[string]string{"app": "web", "tier": "frontend"},
				NetworkInterfaces: []*computepb.NetworkInterface{
					{Network: proto.String(networkURL), NetworkIP: proto.String("10.10.0.5")},
				},
			},
		},
	}

	client := &GCPClient{
		firewalls:    fw,
		instances:    instances,
		rulePrefix:   defaultGCPRulePrefix,
		priorityBase: defaultGCPPriorityBase,
	}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "dns"},
		Spec: policy.NetworkPolicySpec{
			Ingress: []policy.IngressRule{
				{From: policy.IngressSource{PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}}},
					Ports: []policy.PortSpec{{Protocol: "UDP", Port: 53}}},
			},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, projectID, network); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(fw.inserts) != 1 {
		t.Fatalf("expected 1 insert, got %d", len(fw.inserts))
	}
	rule := fw.inserts[0]
	if rule.GetName() == "" || !strings.HasPrefix(rule.GetName(), "ztap-ingress-udp-53-sel-app-web") {
		t.Fatalf("unexpected rule name: %s", rule.GetName())
	}

	if got := rule.GetDirection(); got != "INGRESS" {
		t.Fatalf("unexpected direction: %s", got)
	}
	srcRanges := rule.GetSourceRanges()
	if len(srcRanges) != 1 || srcRanges[0] != "10.10.0.5/32" {
		t.Fatalf("unexpected source ranges: %#v", srcRanges)
	}

	if rule.Priority == nil {
		t.Fatalf("expected priority to be set")
	}

	if fw.lastNetwork != networkURL {
		t.Fatalf("unexpected network url: %s", fw.lastNetwork)
	}
}

func TestGCPSyncPolicyPortRange(t *testing.T) {
	end := 8080
	fw := &mockFirewalls{}
	client := &GCPClient{firewalls: fw, rulePrefix: defaultGCPRulePrefix, priorityBase: defaultGCPPriorityBase}

	np := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "range"},
		Spec: policy.NetworkPolicySpec{
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 8000, EndPort: &end}},
			}},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "demo", "default"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}
	if len(fw.inserts) != 1 {
		t.Fatalf("expected 1 insert, got %d", len(fw.inserts))
	}
	rule := fw.inserts[0]
	if rule.GetDirection() != "EGRESS" {
		t.Fatalf("unexpected direction: %s", rule.GetDirection())
	}
	if len(rule.GetAllowed()) != 1 || len(rule.GetAllowed()[0].Ports) != 1 {
		t.Fatalf("unexpected allowed ports: %#v", rule.GetAllowed())
	}
	if got := rule.GetAllowed()[0].Ports[0]; got != "8000-8080" {
		t.Fatalf("expected port range 8000-8080, got %s", got)
	}
	if !strings.Contains(rule.GetName(), "8000-8080") {
		t.Fatalf("expected rule name to include range, got %s", rule.GetName())
	}
}

func TestGCPDiscoverResources(t *testing.T) {
	projectID := "demo"
	network := "default"
	networkURL := networkSelfLink(projectID, network)

	instances := &mockInstances{
		instances: []*computepb.Instance{
			{
				Name:   proto.String("vm1"),
				Id:     proto.Uint64(1),
				Labels: map[string]string{"app": "web"},
				NetworkInterfaces: []*computepb.NetworkInterface{
					{Network: proto.String(networkURL), NetworkIP: proto.String("10.10.0.5")},
				},
			},
		},
	}

	client := &GCPClient{instances: instances, rulePrefix: defaultGCPRulePrefix, priorityBase: defaultGCPPriorityBase}
	resources, err := client.DiscoverResources(context.Background(), projectID, network)
	if err != nil {
		t.Fatalf("DiscoverResources returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].PrivateIP != "10.10.0.5" {
		t.Fatalf("unexpected private IP: %s", resources[0].PrivateIP)
	}
}
