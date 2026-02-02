package cloud

import (
	"context"
	"errors"
	"testing"

	"ztap/pkg/policy"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// mockEC2Client implements the ec2API interface for testing.
type mockEC2Client struct {
	describeInstancesOutput *ec2.DescribeInstancesOutput
	describeInstancesErr    error

	authorizeInputs []*ec2.AuthorizeSecurityGroupEgressInput
	authorizeErr    error

	describeSGOutput *ec2.DescribeSecurityGroupsOutput
	describeSGErr    error

	revokeInputs []*ec2.RevokeSecurityGroupEgressInput
	revokeErr    error
}

func (m *mockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return m.describeInstancesOutput, m.describeInstancesErr
}

func (m *mockEC2Client) AuthorizeSecurityGroupEgress(ctx context.Context, params *ec2.AuthorizeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
	m.authorizeInputs = append(m.authorizeInputs, params)
	if m.authorizeErr != nil {
		return nil, m.authorizeErr
	}
	return &ec2.AuthorizeSecurityGroupEgressOutput{}, nil
}

func (m *mockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return m.describeSGOutput, m.describeSGErr
}

func (m *mockEC2Client) RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	m.revokeInputs = append(m.revokeInputs, params)
	if m.revokeErr != nil {
		return nil, m.revokeErr
	}
	return &ec2.RevokeSecurityGroupEgressOutput{}, nil
}

func TestMatchResourcesByLabels(t *testing.T) {
	resources := []Resource{
		{ID: "i-1", Labels: map[string]string{"env": "prod", "app": "web"}},
		{ID: "i-2", Labels: map[string]string{"env": "prod", "app": "db"}},
		{ID: "i-3", Labels: map[string]string{"env": "dev", "app": "web"}},
	}

	matched := MatchResourcesByLabels(resources, map[string]string{"env": "prod", "app": "web"})
	if len(matched) != 1 || matched[0].ID != "i-1" {
		t.Fatalf("expected one matching resource (i-1), got %#v", matched)
	}

	matched = MatchResourcesByLabels(resources, map[string]string{"env": "qa"})
	if len(matched) != 0 {
		t.Fatalf("expected no matches, got %#v", matched)
	}
}

func TestDiscoverResources(t *testing.T) {
	mock := &mockEC2Client{
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []types.Reservation{
				{
					Instances: []types.Instance{
						{
							InstanceId:       aws.String("i-123"),
							PrivateIpAddress: aws.String("10.0.0.1"),
							PublicIpAddress:  aws.String("203.0.113.1"),
							State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
							Tags: []types.Tag{
								{Key: aws.String("Name"), Value: aws.String("web-1")},
								{Key: aws.String("env"), Value: aws.String("prod")},
							},
						},
						{
							InstanceId: aws.String("i-terminated"),
							State:      &types.InstanceState{Name: types.InstanceStateNameTerminated},
						},
					},
				},
			},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}
	resources, err := client.DiscoverResources(context.Background())
	if err != nil {
		t.Fatalf("DiscoverResources returned error: %v", err)
	}

	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	res := resources[0]
	if res.ID != "i-123" || res.Name != "web-1" || res.PrivateIP != "10.0.0.1" || res.PublicIP != "203.0.113.1" {
		t.Fatalf("unexpected resource: %#v", res)
	}

	if res.Labels["env"] != "prod" {
		t.Fatalf("expected env label 'prod', got %s", res.Labels["env"])
	}
}

func TestDiscoverResourcesError(t *testing.T) {
	mock := &mockEC2Client{describeInstancesErr: errors.New("boom")}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	_, err := client.DiscoverResources(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSyncPolicyWithIPBlock(t *testing.T) {
	mock := &mockEC2Client{describeSGOutput: &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-123")}}}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	var np policy.NetworkPolicy
	np.Metadata.Name = "allow-db"

	egress := policy.EgressRule{
		To: policy.EgressTarget{
			IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"},
		},
		Ports: []policy.PortSpec{
			{Protocol: "TCP", Port: 5432},
			{Protocol: "UDP", Port: 53},
		},
	}

	np.Spec.Egress = append(np.Spec.Egress, egress)

	if err := client.SyncPolicy(context.Background(), np, "sg-123"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(mock.authorizeInputs) != 2 {
		t.Fatalf("expected 2 authorize calls, got %d", len(mock.authorizeInputs))
	}

	protocols := map[string]bool{}
	for _, call := range mock.authorizeInputs {
		if aws.ToString(call.GroupId) != "sg-123" {
			t.Fatalf("unexpected group id: %s", aws.ToString(call.GroupId))
		}
		if len(call.IpPermissions) != 1 {
			t.Fatalf("expected 1 IP permission, got %d", len(call.IpPermissions))
		}
		perm := call.IpPermissions[0]
		if aws.ToString(perm.IpRanges[0].CidrIp) != "10.0.0.0/24" {
			t.Fatalf("unexpected CIDR: %s", aws.ToString(perm.IpRanges[0].CidrIp))
		}
		protocols[aws.ToString(perm.IpProtocol)] = true
	}
	if !protocols["tcp"] || !protocols["udp"] {
		t.Fatalf("expected tcp and udp protocols, got %#v", protocols)
	}
}

func TestSyncPolicyAuthorizeError(t *testing.T) {
	mock := &mockEC2Client{authorizeErr: errors.New("api failure"), describeSGOutput: &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-456")}}}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	var np policy.NetworkPolicy
	np.Metadata.Name = "allow-web"

	egress := policy.EgressRule{
		To: policy.EgressTarget{
			IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"},
		},
		Ports: []policy.PortSpec{
			{Protocol: "TCP", Port: 443},
		},
	}
	np.Spec.Egress = append(np.Spec.Egress, egress)

	err := client.SyncPolicy(context.Background(), np, "sg-456")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSyncPolicyWithPortRange(t *testing.T) {
	end := 8080
	mock := &mockEC2Client{describeSGOutput: &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-123")}}}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "range"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/24"}},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 8000, EndPort: &end}},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "sg-123"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}
	if len(mock.authorizeInputs) != 1 {
		t.Fatalf("expected 1 authorize call, got %d", len(mock.authorizeInputs))
	}
	perm := mock.authorizeInputs[0].IpPermissions[0]
	if perm.FromPort == nil || *perm.FromPort != 8000 {
		t.Fatalf("expected FromPort 8000, got %#v", perm.FromPort)
	}
	if perm.ToPort == nil || *perm.ToPort != 8080 {
		t.Fatalf("expected ToPort 8080, got %#v", perm.ToPort)
	}
}

func TestSyncPolicyWithSelectorResolution(t *testing.T) {
	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-123")}},
		},
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []types.Reservation{
				{
					Instances: []types.Instance{
						{
							InstanceId:       aws.String("i-1"),
							PrivateIpAddress: aws.String("10.0.0.10"),
							State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
							Tags: []types.Tag{
								{Key: aws.String("app"), Value: aws.String("web")},
								{Key: aws.String("tier"), Value: aws.String("frontend")},
							},
						},
						{
							InstanceId:       aws.String("i-2"),
							PrivateIpAddress: aws.String("10.0.0.11"),
							State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
							Tags: []types.Tag{
								{Key: aws.String("app"), Value: aws.String("db")},
							},
						},
					},
				},
			},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "selector"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To: policy.EgressTarget{
				PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "sg-123"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(mock.authorizeInputs) != 1 {
		t.Fatalf("expected 1 authorize call, got %d", len(mock.authorizeInputs))
	}

	perm := mock.authorizeInputs[0].IpPermissions[0]
	if len(perm.IpRanges) != 1 {
		t.Fatalf("expected 1 ip range, got %d", len(perm.IpRanges))
	}
	if aws.ToString(perm.IpRanges[0].CidrIp) != "10.0.0.10/32" {
		t.Fatalf("unexpected cidr: %s", aws.ToString(perm.IpRanges[0].CidrIp))
	}
}

func TestSyncPolicyRevokesStaleManagedRules(t *testing.T) {
	managedDesc := awsPolicyDescriptionPrefix("cleanup")
	stale := types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(443),
		ToPort:     aws.Int32(443),
		IpRanges: []types.IpRange{
			{CidrIp: aws.String("10.0.0.9/32"), Description: aws.String(managedDesc)},
		},
	}

	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{
				GroupId:             aws.String("sg-123"),
				IpPermissionsEgress: []types.IpPermission{stale},
			}},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "cleanup"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.10/32"}},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "sg-123"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(mock.revokeInputs) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(mock.revokeInputs))
	}
}

func TestSyncPolicyReplaceEgress(t *testing.T) {
	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{
				GroupId: aws.String("sg-123"),
				IpPermissionsEgress: []types.IpPermission{
					{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(80), ToPort: aws.Int32(80)},
				},
			}},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "replace"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.10/32"}},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
		},
	}

	_, err := client.SyncPolicyWithOptions(context.Background(), np, "sg-123", AWSPolicySyncOptions{ReplaceEgress: true})
	if err != nil {
		t.Fatalf("SyncPolicyWithOptions returned error: %v", err)
	}

	if len(mock.revokeInputs) == 0 {
		t.Fatalf("expected revoke call when replace-egress is enabled")
	}
}

func TestSyncPolicyReplaceEgressReauthorizesExistingDesiredRule(t *testing.T) {
	managedDesc := awsPolicyDescriptionPrefix("replace")
	existingDesired := types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(443),
		ToPort:     aws.Int32(443),
		IpRanges: []types.IpRange{
			{CidrIp: aws.String("10.0.0.10/32"), Description: aws.String(managedDesc)},
		},
	}

	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{
				GroupId:             aws.String("sg-123"),
				IpPermissionsEgress: []types.IpPermission{existingDesired},
			}},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "replace"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.10/32"}},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
		},
	}

	_, err := client.SyncPolicyWithOptions(context.Background(), np, "sg-123", AWSPolicySyncOptions{ReplaceEgress: true})
	if err != nil {
		t.Fatalf("SyncPolicyWithOptions returned error: %v", err)
	}
	if len(mock.authorizeInputs) != 1 {
		t.Fatalf("expected 1 authorize call (rule must be re-added), got %d", len(mock.authorizeInputs))
	}
}

func TestSyncPolicyDryRun(t *testing.T) {
	mock := &mockEC2Client{describeSGOutput: &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-123")}}}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "dry"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.10/32"}},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
		},
	}

	_, err := client.SyncPolicyWithOptions(context.Background(), np, "sg-123", AWSPolicySyncOptions{DryRun: true})
	if err != nil {
		t.Fatalf("SyncPolicyWithOptions returned error: %v", err)
	}
	if len(mock.authorizeInputs) != 0 {
		t.Fatalf("expected no authorize calls in dry-run, got %d", len(mock.authorizeInputs))
	}
}

func TestAuthorizeEgressDuplicate(t *testing.T) {
	mock := &mockEC2Client{authorizeErr: errors.New("rule already exists"), describeSGOutput: &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-789")}}}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	if err := client.authorizeEgress(context.Background(), "sg-789", "10.0.0.0/24", "TCP", 80, 80); err != nil {
		t.Fatalf("expected duplicate error to be ignored, got %v", err)
	}
}

func TestSyncPolicyWithSelectorExpressions(t *testing.T) {
	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-123")}},
		},
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []types.Reservation{
				{
					Instances: []types.Instance{
						{
							InstanceId:       aws.String("i-1"),
							PrivateIpAddress: aws.String("10.0.0.20"),
							State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
							Tags: []types.Tag{
								{Key: aws.String("env"), Value: aws.String("prod")},
								{Key: aws.String("role"), Value: aws.String("api")},
							},
						},
					},
				},
			},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	np := policy.NetworkPolicy{Metadata: policy.NetworkPolicyMetadata{Name: "expr"}}
	np.Spec.Egress = []policy.EgressRule{
		{
			To: policy.EgressTarget{
				PodSelector: policy.PodSelectorSpec{
					MatchExpressions: []policy.LabelSelectorRequirement{{Key: "env", Operator: "In", Values: []string{"prod"}}},
				},
			},
			Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
		},
	}

	if err := client.SyncPolicy(context.Background(), np, "sg-123"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(mock.authorizeInputs) != 1 {
		t.Fatalf("expected 1 authorize call, got %d", len(mock.authorizeInputs))
	}
	perm := mock.authorizeInputs[0].IpPermissions[0]
	if aws.ToString(perm.IpRanges[0].CidrIp) != "10.0.0.20/32" {
		t.Fatalf("unexpected cidr: %s", aws.ToString(perm.IpRanges[0].CidrIp))
	}
}

func TestRevokeAllEgress(t *testing.T) {
	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{
				{
					GroupId: aws.String("sg-123"),
					IpPermissionsEgress: []types.IpPermission{
						{
							IpProtocol: aws.String("tcp"),
							FromPort:   aws.Int32(80),
							ToPort:     aws.Int32(80),
						},
					},
				},
			},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}
	if err := client.RevokeAllEgress(context.Background(), "sg-123"); err != nil {
		t.Fatalf("RevokeAllEgress returned error: %v", err)
	}

	if len(mock.revokeInputs) == 0 {
		t.Fatal("expected revoke call, got nil")
	}
	if aws.ToString(mock.revokeInputs[0].GroupId) != "sg-123" {
		t.Fatalf("unexpected group id in revoke: %s", aws.ToString(mock.revokeInputs[0].GroupId))
	}
}

func TestRevokeAllEgressNoRules(t *testing.T) {
	mock := &mockEC2Client{
		describeSGOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{
				GroupId:             aws.String("sg-000"),
				IpPermissionsEgress: []types.IpPermission{},
			}},
		},
	}

	client := &AWSClient{ec2API: mock, region: "us-east-1"}
	if err := client.RevokeAllEgress(context.Background(), "sg-000"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(mock.revokeInputs) != 0 {
		t.Fatalf("expected no revoke call, got %#v", mock.revokeInputs)
	}
}

func TestRevokeAllEgressNotFound(t *testing.T) {
	mock := &mockEC2Client{describeSGOutput: &ec2.DescribeSecurityGroupsOutput{}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	if err := client.RevokeAllEgress(context.Background(), "sg-missing"); err == nil {
		t.Fatal("expected error for missing security group, got nil")
	}
}
