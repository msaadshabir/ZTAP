//go:build windows

package enforcer

import (
	"encoding/binary"
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

	FWP_MATCH_EQUAL            uint32 = 0
	FWP_MATCH_GREATER_OR_EQUAL uint32 = 3
	FWP_MATCH_LESS_OR_EQUAL    uint32 = 4
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
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	LayerALEAuthConnectV6 = GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	LayerALEAuthRecvAcceptV4 = GUID{
		Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
	}
	LayerALEAuthRecvAcceptV6 = GUID{
		Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
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

// V6AddrMask represents an IPv6 address + prefix length used by WFP conditions.
// For a single IP match, use PrefixLength = 128.
type V6AddrMask struct {
	Addr         [16]byte
	PrefixLength uint8
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
			isIPv6 := ip.To4() == nil
			layerKey := LayerALEAuthConnectV4
			var addrCond WFPCondition
			if isIPv6 {
				layerKey = LayerALEAuthConnectV6
				var addr [16]byte
				copy(addr[:], ipnet.IP.To16())
				addrCond = WFPCondition{FieldKey: ConditionIPRemoteAddress, MatchType: FWP_MATCH_EQUAL, Value: V6AddrMask{Addr: addr, PrefixLength: uint8(ones)}}
			} else {
				if bits != 32 {
					return nil, fmt.Errorf("invalid egress CIDR %s", egress.To.IPBlock.CIDR)
				}
				mask := ipMaskToUint32(ipnet.Mask)
				destIP := ipToUint32(ipnet.IP.To4())
				addrCond = WFPCondition{FieldKey: ConditionIPRemoteAddress, MatchType: FWP_MATCH_EQUAL, Value: V4AddrMask{Addr: destIP, Mask: mask}}
			}

			for _, port := range egress.Ports {
				if port.PortName != "" {
					return nil, fmt.Errorf("named ports are not supported by WFP translation")
				}
				start := port.Port
				end := port.Port
				if port.EndPort != nil {
					end = *port.EndPort
				}
				proto := strings.ToUpper(port.Protocol)
				isICMP := proto == "ICMP"
				protoNum := protocolToNum(port.Protocol)
				if isIPv6 && isICMP {
					protoNum = 58
				}

				conds := []WFPCondition{addrCond}
				if !isICMP {
					if end < start {
						return nil, fmt.Errorf("invalid port range %d-%d", start, end)
					}
					if start == end {
						conds = append(conds, WFPCondition{FieldKey: ConditionIPRemotePort, MatchType: FWP_MATCH_EQUAL, Value: uint16(start)})
					} else {
						conds = append(conds,
							WFPCondition{FieldKey: ConditionIPRemotePort, MatchType: FWP_MATCH_GREATER_OR_EQUAL, Value: uint16(start)},
							WFPCondition{FieldKey: ConditionIPRemotePort, MatchType: FWP_MATCH_LESS_OR_EQUAL, Value: uint16(end)},
						)
					}
				}
				conds = append(conds, WFPCondition{FieldKey: ConditionIPProtocol, MatchType: FWP_MATCH_EQUAL, Value: protoNum})
				portLabel := fmt.Sprintf("%d", start)
				if end > start {
					portLabel = fmt.Sprintf("%d-%d", start, end)
				}
				spec := WFPSpec{
					Name:        fmt.Sprintf("ZTAP-Egress-%s", p.Metadata.Name),
					Description: fmt.Sprintf("Allow egress to %s:%s", egress.To.IPBlock.CIDR, portLabel),
					LayerKey:    layerKey,
					SublayerKey: ZTAPSublayerGUID,
					ProviderKey: &ZTAPProviderGUID,
					Weight:      100,
					ActionType:  FWP_ACTION_PERMIT,
					Conditions:  conds,
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
			isIPv6 := ip.To4() == nil
			layerKey := LayerALEAuthRecvAcceptV4
			var addrCond WFPCondition
			if isIPv6 {
				layerKey = LayerALEAuthRecvAcceptV6
				var addr [16]byte
				copy(addr[:], ipnet.IP.To16())
				addrCond = WFPCondition{FieldKey: ConditionIPRemoteAddress, MatchType: FWP_MATCH_EQUAL, Value: V6AddrMask{Addr: addr, PrefixLength: uint8(ones)}}
			} else {
				if bits != 32 {
					return nil, fmt.Errorf("invalid ingress CIDR %s", ingress.From.IPBlock.CIDR)
				}
				mask := ipMaskToUint32(ipnet.Mask)
				srcIP := ipToUint32(ipnet.IP.To4())
				addrCond = WFPCondition{FieldKey: ConditionIPRemoteAddress, MatchType: FWP_MATCH_EQUAL, Value: V4AddrMask{Addr: srcIP, Mask: mask}}
			}

			for _, port := range ingress.Ports {
				if port.PortName != "" {
					return nil, fmt.Errorf("named ports are not supported by WFP translation")
				}
				start := port.Port
				end := port.Port
				if port.EndPort != nil {
					end = *port.EndPort
				}
				proto := strings.ToUpper(port.Protocol)
				isICMP := proto == "ICMP"
				protoNum := protocolToNum(port.Protocol)
				if isIPv6 && isICMP {
					protoNum = 58
				}

				conds := []WFPCondition{addrCond}
				if !isICMP {
					if end < start {
						return nil, fmt.Errorf("invalid port range %d-%d", start, end)
					}
					if start == end {
						conds = append(conds, WFPCondition{FieldKey: ConditionIPLocalPort, MatchType: FWP_MATCH_EQUAL, Value: uint16(start)})
					} else {
						conds = append(conds,
							WFPCondition{FieldKey: ConditionIPLocalPort, MatchType: FWP_MATCH_GREATER_OR_EQUAL, Value: uint16(start)},
							WFPCondition{FieldKey: ConditionIPLocalPort, MatchType: FWP_MATCH_LESS_OR_EQUAL, Value: uint16(end)},
						)
					}
				}
				conds = append(conds, WFPCondition{FieldKey: ConditionIPProtocol, MatchType: FWP_MATCH_EQUAL, Value: protoNum})
				portLabel := fmt.Sprintf("%d", start)
				if end > start {
					portLabel = fmt.Sprintf("%d-%d", start, end)
				}
				spec := WFPSpec{
					Name:        fmt.Sprintf("ZTAP-Ingress-%s", p.Metadata.Name),
					Description: fmt.Sprintf("Allow ingress from %s to port %s", ingress.From.IPBlock.CIDR, portLabel),
					LayerKey:    layerKey,
					SublayerKey: ZTAPSublayerGUID,
					ProviderKey: &ZTAPProviderGUID,
					Weight:      100,
					ActionType:  FWP_ACTION_PERMIT,
					Conditions:  conds,
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
	if ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func ipMaskToUint32(mask net.IPMask) uint32 {
	if len(mask) != 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(mask)
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
