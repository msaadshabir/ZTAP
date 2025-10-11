package cloud

import (
	"context"
	"fmt"
	"log"
	"strings"

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

// NewAWSClient creates a new AWS client
func NewAWSClient(region string) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSClient{
		ec2API: ec2.NewFromConfig(cfg),
		region: region,
	}, nil
}

// DiscoverResources finds all EC2 instances and their metadata
func (c *AWSClient) DiscoverResources() ([]Resource, error) {
	input := &ec2.DescribeInstancesInput{}
	result, err := c.ec2API.DescribeInstances(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	var resources []Resource
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State != nil && instance.State.Name == types.InstanceStateNameTerminated {
				continue
			}

			labels := make(map[string]string)
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

// SyncPolicy converts ZTAP policy to AWS Security Group rules
func (c *AWSClient) SyncPolicy(p policy.NetworkPolicy, sgID string) error {
	log.Printf("Syncing policy '%s' to Security Group %s", p.Metadata.Name, sgID)

	// For each egress rule in policy
	for _, egress := range p.Spec.Egress {
		// Convert to AWS Security Group rule
		if egress.To.IPBlock.CIDR != "" {
			for _, port := range egress.Ports {
				err := c.authorizeEgress(sgID, egress.To.IPBlock.CIDR, port.Protocol, port.Port)
				if err != nil {
					return fmt.Errorf("failed to authorize egress: %w", err)
				}
			}
		}

		// Handle label-based rules (resolve labels to IPs first)
		if len(egress.To.PodSelector.MatchLabels) > 0 {
			log.Printf("Note: Label-based rules require IP resolution from inventory")
			// In production: query discovered resources, match labels, extract IPs
			// For now: log as warning
		}
	}

	return nil
}

// authorizeEgress adds an egress rule to the Security Group
func (c *AWSClient) authorizeEgress(sgID, cidr, protocol string, port int) error {
	// Convert protocol to lowercase (AWS uses lowercase)
	proto := strings.ToLower(protocol)

	// Note: AWS Security Groups are stateful, so egress rules automatically allow responses
	input := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String(proto),
				FromPort:   aws.Int32(int32(port)),
				ToPort:     aws.Int32(int32(port)),
				IpRanges: []types.IpRange{
					{
						CidrIp:      aws.String(cidr),
						Description: aws.String("Managed by ZTAP"),
					},
				},
			},
		},
	}

	_, err := c.ec2API.AuthorizeSecurityGroupEgress(context.TODO(), input)
	if err != nil {
		// Ignore "duplicate rule" errors
		if strings.Contains(err.Error(), "already exists") {
			log.Printf("Rule already exists: %s:%d -> %s", protocol, port, cidr)
			return nil
		}
		return err
	}

	log.Printf("Authorized egress: %s:%d -> %s in %s", protocol, port, cidr, sgID)
	return nil
}

// RevokeAllEgress removes all egress rules from a Security Group (for cleanup)
func (c *AWSClient) RevokeAllEgress(sgID string) error {
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	}

	result, err := c.ec2API.DescribeSecurityGroups(context.TODO(), input)
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

	_, err = c.ec2API.RevokeSecurityGroupEgress(context.TODO(), revokeInput)
	if err != nil {
		return fmt.Errorf("failed to revoke egress rules: %w", err)
	}

	log.Printf("Revoked all egress rules from %s", sgID)
	return nil
}

// MatchResourcesByLabels finds resources matching the given labels
func MatchResourcesByLabels(resources []Resource, labels map[string]string) []Resource {
	var matched []Resource
	for _, r := range resources {
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
