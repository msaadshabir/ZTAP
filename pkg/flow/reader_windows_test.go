//go:build windows

package flow

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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

func TestWfpNetEvent3ToRawFlowEvent_V4OutboundAllow(t *testing.T) {
	var allow fwpmNetEventClassifyAllow0
	allow.MsFwpDirection = fwpDirectionOut

	var ev fwpmNetEvent3
	ev.Type = fwpmNetEventTypeClassifyAllow
	ev.Data = uintptr(unsafe.Pointer(&allow))
	ev.Header.Header2.Prefix.IPVersion = fwpIPVersionV4
	ev.Header.Header2.Prefix.IPProto = ProtocolTCP
	copy(ev.Header.Header2.Prefix.LocalAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.Header.Header2.Prefix.RemoteAddr[:4], []byte{1, 2, 3, 4})
	ev.Header.Header2.Prefix.LocalPort = 50000
	ev.Header.Header2.Prefix.RemotePort = 443

	raw, ok := wfpNetEvent3ToRawFlowEvent(&ev)
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
}

func TestWfpNetEvent3ToRawFlowEvent_V6RoundTrip(t *testing.T) {
	local := net.ParseIP("2001:db8::1").To16()
	remote := net.ParseIP("2001:db8::2").To16()
	if local == nil || remote == nil {
		t.Fatalf("failed to parse IPv6")
	}

	var allow fwpmNetEventClassifyAllow0
	allow.MsFwpDirection = fwpDirectionOut

	var ev fwpmNetEvent3
	ev.Type = fwpmNetEventTypeClassifyAllow
	ev.Data = uintptr(unsafe.Pointer(&allow))
	ev.Header.Header2.Prefix.IPVersion = fwpIPVersionV6
	ev.Header.Header2.Prefix.IPProto = ProtocolUDP
	copy(ev.Header.Header2.Prefix.LocalAddr[:], local)
	copy(ev.Header.Header2.Prefix.RemoteAddr[:], remote)
	ev.Header.Header2.Prefix.LocalPort = 40000
	ev.Header.Header2.Prefix.RemotePort = 53

	raw, ok := wfpNetEvent3ToRawFlowEvent(&ev)
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

func TestWfpNetEvent2ToWfpEvent_IgnoresNonAllowDrop(t *testing.T) {
	var ev fwpmNetEvent2
	ev.Type = fwpmNetEventTypeIkeQmFailure
	if _, ok := wfpNetEvent2ToWfpEvent(&ev); ok {
		t.Fatalf("expected not ok")
	}
}

func TestWfpEventToRawFlowEvent_IgnoresUnknownType(t *testing.T) {
	r := &WindowsReader{}
	_, ok := r.wfpEventToRawFlowEvent(wfpEvent{typ: fwpmNetEventTypeIkeMmFailure})
	if ok {
		t.Fatalf("expected not ok")
	}
}

func TestWfpEventToRawFlowEvent_CapabilityTypeMapping(t *testing.T) {
	r := &WindowsReader{}
	ev := wfpEvent{typ: fwpmNetEventTypeCapabilityDrop, msDir: fwpDirectionOut, ipVersion: fwpIPVersionV4, proto: ProtocolTCP}
	copy(ev.localAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.remoteAddr[:4], []byte{1, 2, 3, 4})
	raw, ok := r.wfpEventToRawFlowEvent(ev)
	if !ok {
		t.Fatalf("expected ok")
	}
	if raw.Action != ActionBlocked {
		t.Fatalf("Action=%d want %d", raw.Action, ActionBlocked)
	}
}

func TestWfpEventToRawFlowEvent_V4InboundAllowSwapsTuple(t *testing.T) {
	r := &WindowsReader{}
	ev := wfpEvent{
		typ:        fwpmNetEventTypeClassifyAllow,
		msDir:      fwpDirectionIn,
		ipVersion:  fwpIPVersionV4,
		proto:      ProtocolTCP,
		localPort:  22,
		remotePort: 54321,
	}
	copy(ev.localAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.remoteAddr[:4], []byte{9, 9, 9, 9})

	raw, ok := r.wfpEventToRawFlowEvent(ev)
	if !ok {
		t.Fatalf("expected ok")
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

func TestWfpEventToRawFlowEvent_ForwardDirectionDefaultsEgress(t *testing.T) {
	r := &WindowsReader{}
	ev := wfpEvent{typ: fwpmNetEventTypeClassifyAllow, msDir: fwpDirectionForward, ipVersion: fwpIPVersionV4}
	copy(ev.localAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.remoteAddr[:4], []byte{1, 2, 3, 4})
	raw, ok := r.wfpEventToRawFlowEvent(ev)
	if !ok {
		t.Fatalf("expected ok")
	}
	if raw.Direction != DirectionEgress {
		t.Fatalf("Direction=%d want %d", raw.Direction, DirectionEgress)
	}
}

func TestEnqueueWfpEvent_DropsWhenQueueFull(t *testing.T) {
	r := &WindowsReader{}
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	r.inCh = make(chan wfpEvent, 1)

	// Fill queue.
	r.inCh <- wfpEvent{typ: fwpmNetEventTypeClassifyDrop}

	// Next enqueue should drop.
	r.enqueueWfpEvent(wfpEvent{typ: fwpmNetEventTypeClassifyDrop})
	if r.droppedInCh.Load() != 1 {
		t.Fatalf("droppedInCh=%d want 1", r.droppedInCh.Load())
	}
}

func TestRunWorker_EmitsTimestamp(t *testing.T) {
	old := uptimeNsFunc
	uptimeNsFunc = func() int64 { return 123 }
	defer func() { uptimeNsFunc = old }()

	r := &WindowsReader{}
	out := make(chan RawFlowEvent, 1)
	r.eventCh = out

	in := make(chan wfpEvent, 1)
	stopCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.runWorker(ctx, stopCh, in, false)

	ev := wfpEvent{typ: fwpmNetEventTypeClassifyAllow, msDir: fwpDirectionOut, ipVersion: fwpIPVersionV4, proto: ProtocolTCP}
	copy(ev.localAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.remoteAddr[:4], []byte{1, 2, 3, 4})
	in <- ev

	select {
	case got := <-out:
		if got.TimestampNs != 123 {
			t.Fatalf("TimestampNs=%d want 123", got.TimestampNs)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for event")
	}
}

func TestRunWorker_DeduperDropsDuplicate(t *testing.T) {
	old := uptimeNsFunc
	uptimeNsFunc = func() int64 { return 1000 }
	defer func() { uptimeNsFunc = old }()

	r := &WindowsReader{}
	r.deduper = newWfpDeduper(1000, 1_000_000_000) // 1s window
	out := make(chan RawFlowEvent, 2)
	r.eventCh = out

	in := make(chan wfpEvent, 2)
	stopCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.runWorker(ctx, stopCh, in, false)

	ev := wfpEvent{typ: fwpmNetEventTypeClassifyDrop, msDir: fwpDirectionOut, ipVersion: fwpIPVersionV4, proto: ProtocolTCP}
	copy(ev.localAddr[:4], []byte{10, 0, 0, 10})
	copy(ev.remoteAddr[:4], []byte{1, 2, 3, 4})

	in <- ev
	in <- ev

	// We expect exactly 1 emitted event.
	select {
	case <-out:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for first event")
	}

	select {
	case <-out:
		t.Fatalf("expected duplicate to be dropped")
	case <-time.After(200 * time.Millisecond):
		// ok
	}
}

func TestFilterOwnerCache_BoundedReset(t *testing.T) {
	c := newFilterOwnerCache(2)
	c.set(1, true)
	c.set(2, false)
	c.set(3, true) // triggers reset

	if v, ok := c.get(3); !ok || !v {
		t.Fatalf("expected id=3 to exist and be true")
	}
	// At least one of the earlier entries should be gone after reset.
	if _, ok := c.get(1); ok {
		if _, ok2 := c.get(2); ok2 {
			t.Fatalf("expected cache reset to evict earlier entries")
		}
	}
}

func TestLayerKeyCache_SetGet(t *testing.T) {
	c := newLayerKeyCache()
	g := net.IPv4(1, 2, 3, 4) // just to use something deterministic for bytes
	var key windows.GUID
	copy(key.Data4[:], []byte(g.To4()))

	c.set(10, key)
	got, ok := c.get(10)
	if !ok {
		t.Fatalf("expected ok")
	}
	if got.Data4 != key.Data4 {
		t.Fatalf("unexpected guid")
	}
}

func TestWfpDeduper_Window(t *testing.T) {
	d := newWfpDeduper(10, 100)
	k := wfpDedupKey{}
	if d.SeenRecently(k, 1000) {
		t.Fatalf("first insert should not be seen")
	}
	if !d.SeenRecently(k, 1050) {
		t.Fatalf("expected seen within window")
	}
	if d.SeenRecently(k, 2000) {
		t.Fatalf("expected not seen outside window")
	}
}

func TestInferDirectionFromLayerKey(t *testing.T) {
	if dir, ok := inferDirectionFromLayerKey(fwpmLayerAleAuthConnectV4); !ok || dir != DirectionEgress {
		t.Fatalf("expected connect v4 to infer egress")
	}
	if dir, ok := inferDirectionFromLayerKey(fwpmLayerAleAuthRecvAcceptV4); !ok || dir != DirectionIngress {
		t.Fatalf("expected recv_accept v4 to infer ingress")
	}
}

// Ensure WindowsReader methods used in tests can be called without full initialization.
func TestWindowsReader_ZeroValueDoesNotPanic(t *testing.T) {
	r := &WindowsReader{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopCh := make(chan struct{})
	close(stopCh)
	in := make(chan wfpEvent)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.runWorker(ctx, stopCh, in, false)
	}()
	wg.Wait()
}
