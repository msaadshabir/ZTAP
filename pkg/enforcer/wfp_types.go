//go:build windows

package enforcer

import (
	"fmt"
	"net"
	"strings"
	"ztap/pkg/policy"
)

// GUID represents a globally unique identifier.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WFP constants
const (
	FWP_ACTION_BLOCK  uint32 = 0x00000001
	FWP_ACTION_PERMIT uint32 = 0x00000002

	FWP_MATCH_EQUAL uint32 = 0
)

// ZTAP WFP GUIDs
var (
	ZTAPProviderGUID = GUID{
		Data1: 0x7F8E9D0C, Data2: 0x1B2A, Data3: 0x4D3E,
		Data4: [8]byte{0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A},
	}
	ZTAPSublayerGUID = GUID{
		Data1: 0xA1B2C3D4, Data2: 0xE5F6, Data3: 0x4A5B,
		Data4: [8]byte{0x8C, 0x9D, 0x0E, 0x1F, 0x2A, 0x3B, 0x4C, 0x5D},
	}

	LayerALEAuthConnectV4 = GUID{
		Data1: 0xc38d3328, Data2: 0x5c62, Data3: 0x4a39,
		Data4: [8]byte{0x83, 0x0e, 0xcd, 0x39, 0xda, 0x39, 0x05, 0xfb},
	}
	LayerALEAuthRecvAcceptV4 = GUID{
		Data1: 0xec9038a3, Data2: 0x647f, Data3: 0x40f3,
		Data4: [8]byte{0xa0, 0x04, 0x1c, 0x15, 0x0b, 0x31, 0xdb, 0x0a},
	}

	ConditionIPRemoteAddress = GUID{
		Data1: 0x39713511, Data2: 0x0858, Data3: 0x11d9,
		Data4: [8]byte{0x97, 0x4a, 0x00, 0x0a, 0x95, 0xf7, 0x2a, 0x19},
	}
	ConditionIPRemotePort = GUID{
		Data1: 0x39713512, Data2: 0x0858, Data3: 0x11d9,
		Data4: [8]byte{0x97, 0x4a, 0x00, 0x0a, 0x95, 0xf7, 0x2a, 0x19},
	}
	ConditionIPProtocol = GUID{
		Data1: 0x39713513, Data2: 0x0858, Data3: 0x11d9,
		Data4: [8]byte{0x97, 0x4a, 0x00, 0x0a, 0x95, 0xf7, 0x2a, 0x19},
	}
	ConditionIPLocalPort = GUID{
		Data1: 0x39713514, Data2: 0x0858, Data3: 0x11d9,
		Data4: [8]byte{0x97, 0x4a, 0x00, 0x0a, 0x95, 0xf7, 0x2a, 0x19},
	}
)

// wfpEngine defines the interface for interacting with Windows Filtering Platform.
type wfpEngine interface {
	Open() error
	Close() error
	BeginTransaction() error
	CommitTransaction() error
	AbortTransaction() error

	AddProvider(name, description string, guid *GUID) error
	AddSublayer(name, description string, guid *GUID, providerGuid *GUID, weight uint16) error

	AddFilter(filter *WFPSpec) error
	DeleteFilterByKey(key *GUID) error
	DeleteFiltersByProvider(providerGuid *GUID) error
}

// WFPSpec represents a simplified WFP filter specification for translation.
type WFPSpec struct {
	Name        string
	Description string
	LayerKey    GUID
	SublayerKey GUID
	ProviderKey *GUID
	Weight      uint64
	ActionType  uint32
	Conditions  []WFPCondition
}

// WFPCondition represents a single condition in a WFP filter.
type WFPCondition struct {
	FieldKey  GUID
	MatchType uint32
	Value     any
}

// V4AddrMask represents an IPv4 address + mask pair used by WFP conditions.
// For a single IP match, use Mask = 0xffffffff.
type V4AddrMask struct {
	Addr uint32
	Mask uint32
}

// TranslatePolicyToWFP converts a ZTAP policy to a set of WFP filter specifications.
func TranslatePolicyToWFP(p policy.NetworkPolicy) ([]WFPSpec, error) {
	var specs []WFPSpec

	// Handle egress rules
	for _, egress := range p.Spec.Egress {
		if egress.To.IPBlock.CIDR != "" {
			ip, ipnet, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
			if err != nil {
				return nil, fmt.Errorf("invalid egress CIDR %s: %w", egress.To.IPBlock.CIDR, err)
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones != 32 {
				return nil, fmt.Errorf("egress CIDR %s is not supported on windows yet (only /32)", egress.To.IPBlock.CIDR)
			}

			destIP := ipToUint32(ip.To4())

			for _, port := range egress.Ports {
				spec := WFPSpec{
					Name:        fmt.Sprintf("ZTAP-Egress-%s", p.Metadata.Name),
					Description: fmt.Sprintf("Allow egress to %s:%d", egress.To.IPBlock.CIDR, port.Port),
					LayerKey:    LayerALEAuthConnectV4,
					SublayerKey: ZTAPSublayerGUID,
					ProviderKey: &ZTAPProviderGUID,
					Weight:      100,
					ActionType:  FWP_ACTION_PERMIT,
					Conditions: []WFPCondition{
						{FieldKey: ConditionIPRemoteAddress, MatchType: FWP_MATCH_EQUAL, Value: V4AddrMask{Addr: destIP, Mask: 0xffffffff}},
						{FieldKey: ConditionIPRemotePort, MatchType: FWP_MATCH_EQUAL, Value: uint16(port.Port)},
						{FieldKey: ConditionIPProtocol, MatchType: FWP_MATCH_EQUAL, Value: protocolToNum(port.Protocol)},
					},
				}
				specs = append(specs, spec)
			}
		}
	}

	// Handle ingress rules
	for _, ingress := range p.Spec.Ingress {
		if ingress.From.IPBlock.CIDR != "" {
			ip, ipnet, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
			if err != nil {
				return nil, fmt.Errorf("invalid ingress CIDR %s: %w", ingress.From.IPBlock.CIDR, err)
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones != 32 {
				return nil, fmt.Errorf("ingress CIDR %s is not supported on windows yet (only /32)", ingress.From.IPBlock.CIDR)
			}

			srcIP := ipToUint32(ip.To4())

			for _, port := range ingress.Ports {
				spec := WFPSpec{
					Name:        fmt.Sprintf("ZTAP-Ingress-%s", p.Metadata.Name),
					Description: fmt.Sprintf("Allow ingress from %s to port %d", ingress.From.IPBlock.CIDR, port.Port),
					LayerKey:    LayerALEAuthRecvAcceptV4,
					SublayerKey: ZTAPSublayerGUID,
					ProviderKey: &ZTAPProviderGUID,
					Weight:      100,
					ActionType:  FWP_ACTION_PERMIT,
					Conditions: []WFPCondition{
						{FieldKey: ConditionIPRemoteAddress, MatchType: FWP_MATCH_EQUAL, Value: V4AddrMask{Addr: srcIP, Mask: 0xffffffff}},
						{FieldKey: ConditionIPLocalPort, MatchType: FWP_MATCH_EQUAL, Value: uint16(port.Port)},
						{FieldKey: ConditionIPProtocol, MatchType: FWP_MATCH_EQUAL, Value: protocolToNum(port.Protocol)},
					},
				}
				specs = append(specs, spec)
			}
		}
	}

	return specs, nil
}

func ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func protocolToNum(proto string) uint8 {
	switch strings.ToUpper(proto) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	default:
		return 0
	}
}
