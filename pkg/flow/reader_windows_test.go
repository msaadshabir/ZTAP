//go:build windows

package flow

import (
	"net"
	"testing"
	"time"
	"unsafe"
)

func TestWfpNetEvent2ToRawFlowEvent_V4OutboundAllow(t *testing.T) {
	var allow fwpmNetEventClassifyAllow0
	allow.MsFwpDirection = fwpDirectionOut

	var ev fwpmNetEvent2
	ev.Type = fwpmNetEventTypeClassifyAllow
	ev.Data = uintptr(unsafe.Pointer(&allow))
	ev.Header.Prefix.IPVersion = fwpIPVersionV4
	ev.Header.Prefix.IPProto = ProtocolTCP
	copy(ev.Header.Prefix.LocalAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.Header.Prefix.RemoteAddr[:4], []byte{1, 2, 3, 4})
	ev.Header.Prefix.LocalPort = 50000
	ev.Header.Prefix.RemotePort = 443

	raw, ok := wfpNetEvent2ToRawFlowEvent(&ev)
	if !ok {
		t.Fatalf("expected ok")
	}
	if raw.Action != ActionAllowed {
		t.Fatalf("Action=%d want %d", raw.Action, ActionAllowed)
	}
	if raw.Direction != DirectionEgress {
		t.Fatalf("Direction=%d want %d", raw.Direction, DirectionEgress)
	}
	if raw.Family != 4 {
		t.Fatalf("Family=%d want 4", raw.Family)
	}
	if raw.Protocol != ProtocolTCP {
		t.Fatalf("Protocol=%d want %d", raw.Protocol, ProtocolTCP)
	}
	if raw.SrcIP[0] != 0x0A00000A {
		t.Fatalf("SrcIP[0]=0x%08x want 0x0A00000A", raw.SrcIP[0])
	}
	if raw.DestIP[0] != 0x01020304 {
		t.Fatalf("DestIP[0]=0x%08x want 0x01020304", raw.DestIP[0])
	}
	if raw.SrcPort != 50000 || raw.DestPort != 443 {
		t.Fatalf("ports src=%d dst=%d", raw.SrcPort, raw.DestPort)
	}
}

func TestWfpNetEvent2ToRawFlowEvent_V4InboundDrop(t *testing.T) {
	var drop fwpmNetEventClassifyDrop1
	drop.MsFwpDirection = fwpDirectionIn

	var ev fwpmNetEvent2
	ev.Type = fwpmNetEventTypeClassifyDrop
	ev.Data = uintptr(unsafe.Pointer(&drop))
	ev.Header.Prefix.IPVersion = fwpIPVersionV4
	ev.Header.Prefix.IPProto = ProtocolTCP
	copy(ev.Header.Prefix.LocalAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.Header.Prefix.RemoteAddr[:4], []byte{9, 9, 9, 9})
	ev.Header.Prefix.LocalPort = 22
	ev.Header.Prefix.RemotePort = 54321

	raw, ok := wfpNetEvent2ToRawFlowEvent(&ev)
	if !ok {
		t.Fatalf("expected ok")
	}
	if raw.Action != ActionBlocked {
		t.Fatalf("Action=%d want %d", raw.Action, ActionBlocked)
	}
	if raw.Direction != DirectionIngress {
		t.Fatalf("Direction=%d want %d", raw.Direction, DirectionIngress)
	}
	// For ingress we expect remote -> local.
	if raw.SrcIP[0] != 0x09090909 {
		t.Fatalf("SrcIP[0]=0x%08x want 0x09090909", raw.SrcIP[0])
	}
	if raw.DestIP[0] != 0x0A00000A {
		t.Fatalf("DestIP[0]=0x%08x want 0x0A00000A", raw.DestIP[0])
	}
	if raw.SrcPort != 54321 || raw.DestPort != 22 {
		t.Fatalf("ports src=%d dst=%d", raw.SrcPort, raw.DestPort)
	}
}

func TestWfpNetEvent2ToRawFlowEvent_V6RoundTrip(t *testing.T) {
	local := net.ParseIP("2001:db8::1").To16()
	remote := net.ParseIP("2001:db8::2").To16()
	if local == nil || remote == nil {
		t.Fatalf("failed to parse IPv6")
	}

	var allow fwpmNetEventClassifyAllow0
	allow.MsFwpDirection = fwpDirectionOut

	var ev fwpmNetEvent2
	ev.Type = fwpmNetEventTypeClassifyAllow
	ev.Data = uintptr(unsafe.Pointer(&allow))
	ev.Header.Prefix.IPVersion = fwpIPVersionV6
	ev.Header.Prefix.IPProto = ProtocolUDP
	copy(ev.Header.Prefix.LocalAddr[:], local)
	copy(ev.Header.Prefix.RemoteAddr[:], remote)
	ev.Header.Prefix.LocalPort = 40000
	ev.Header.Prefix.RemotePort = 53

	raw, ok := wfpNetEvent2ToRawFlowEvent(&ev)
	if !ok {
		t.Fatalf("expected ok")
	}

	bootTime := time.Now().Add(-10 * time.Second)
	fe := raw.ToFlowEvent(bootTime)
	if !fe.SourceIP.Equal(net.IP(local)) {
		t.Fatalf("source=%s want %s", fe.SourceIP, net.IP(local))
	}
	if !fe.DestIP.Equal(net.IP(remote)) {
		t.Fatalf("dest=%s want %s", fe.DestIP, net.IP(remote))
	}
}
