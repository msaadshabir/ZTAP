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

	revokeInput *ec2.RevokeSecurityGroupEgressInput
	revokeErr   error
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
	m.revokeInput = params
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
	resources, err := client.DiscoverResources()
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

	_, err := client.DiscoverResources()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSyncPolicyWithIPBlock(t *testing.T) {
	mock := &mockEC2Client{}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	var np policy.NetworkPolicy
	np.Metadata.Name = "allow-db"

	egress := struct {
		To struct {
			PodSelector struct {
				MatchLabels map[string]string `yaml:"matchLabels"`
			} `yaml:"podSelector,omitempty"`
			IPBlock struct {
				CIDR string `yaml:"cidr"`
			} `yaml:"ipBlock,omitempty"`
		} `yaml:"to"`
		Ports []struct {
			Protocol string `yaml:"protocol"`
			Port     int    `yaml:"port"`
		} `yaml:"ports"`
	}{}

	egress.To.IPBlock.CIDR = "10.0.0.0/24"
	egress.Ports = append(egress.Ports, struct {
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
	}{Protocol: "TCP", Port: 5432})
	egress.Ports = append(egress.Ports, struct {
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
	}{Protocol: "UDP", Port: 53})

	np.Spec.Egress = append(np.Spec.Egress, egress)

	if err := client.SyncPolicy(np, "sg-123"); err != nil {
		t.Fatalf("SyncPolicy returned error: %v", err)
	}

	if len(mock.authorizeInputs) != 2 {
		t.Fatalf("expected 2 authorize calls, got %d", len(mock.authorizeInputs))
	}

	first := mock.authorizeInputs[0]
	if aws.ToString(first.GroupId) != "sg-123" {
		t.Fatalf("unexpected group id: %s", aws.ToString(first.GroupId))
	}
	if len(first.IpPermissions) != 1 {
		t.Fatalf("expected 1 IP permission, got %d", len(first.IpPermissions))
	}
	perm := first.IpPermissions[0]
	if aws.ToString(perm.IpProtocol) != "tcp" {
		t.Fatalf("expected protocol tcp, got %s", aws.ToString(perm.IpProtocol))
	}
	if aws.ToString(perm.IpRanges[0].CidrIp) != "10.0.0.0/24" {
		t.Fatalf("unexpected CIDR: %s", aws.ToString(perm.IpRanges[0].CidrIp))
	}
}

func TestSyncPolicyAuthorizeError(t *testing.T) {
	mock := &mockEC2Client{authorizeErr: errors.New("api failure")}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	var np policy.NetworkPolicy
	np.Metadata.Name = "allow-web"

	egress := struct {
		To struct {
			PodSelector struct {
				MatchLabels map[string]string `yaml:"matchLabels"`
			} `yaml:"podSelector,omitempty"`
			IPBlock struct {
				CIDR string `yaml:"cidr"`
			} `yaml:"ipBlock,omitempty"`
		} `yaml:"to"`
		Ports []struct {
			Protocol string `yaml:"protocol"`
			Port     int    `yaml:"port"`
		} `yaml:"ports"`
	}{}
	egress.To.IPBlock.CIDR = "10.0.0.0/24"
	egress.Ports = append(egress.Ports, struct {
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
	}{Protocol: "TCP", Port: 443})
	np.Spec.Egress = append(np.Spec.Egress, egress)

	err := client.SyncPolicy(np, "sg-456")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAuthorizeEgressDuplicate(t *testing.T) {
	mock := &mockEC2Client{authorizeErr: errors.New("rule already exists")}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	if err := client.authorizeEgress("sg-789", "10.0.0.0/24", "TCP", 80); err != nil {
		t.Fatalf("expected duplicate error to be ignored, got %v", err)
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
	if err := client.RevokeAllEgress("sg-123"); err != nil {
		t.Fatalf("RevokeAllEgress returned error: %v", err)
	}

	if mock.revokeInput == nil {
		t.Fatal("expected revoke call, got nil")
	}
	if aws.ToString(mock.revokeInput.GroupId) != "sg-123" {
		t.Fatalf("unexpected group id in revoke: %s", aws.ToString(mock.revokeInput.GroupId))
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
	if err := client.RevokeAllEgress("sg-000"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if mock.revokeInput != nil {
		t.Fatalf("expected no revoke call, got %#v", mock.revokeInput)
	}
}

func TestRevokeAllEgressNotFound(t *testing.T) {
	mock := &mockEC2Client{describeSGOutput: &ec2.DescribeSecurityGroupsOutput{}}
	client := &AWSClient{ec2API: mock, region: "us-east-1"}

	if err := client.RevokeAllEgress("sg-missing"); err == nil {
		t.Fatal("expected error for missing security group, got nil")
	}
}
