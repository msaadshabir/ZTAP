//go:build windows && integration

package flow

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFwpmTransactionBegin0        = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0       = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0        = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0             = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmSubLayerAdd0             = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0               = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0       = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFilterCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = modfwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
)

const (
	fwpActionBlock  uint32 = 0x00000001
	fwpActionPermit uint32 = 0x00000002

	fwpDataTypeUint8      uint32  = 1
	fwpDataTypeUint16     uint32  = 2
	fwpDataTypeUint64     uint32  = 4
	fwpDataTypeV4AddrMask uint32  = 19
	fwpEAlreadyExists     uintptr = 0x80320009
	fwpEFilterNotFound    uintptr = 0x80320004
)

func newTestGUID() windows.GUID {
	n := uint64(time.Now().UnixNano())
	return windows.GUID{
		Data1: uint32(n),
		Data2: uint16(n >> 32),
		Data3: uint16(n >> 48),
		Data4: [8]byte{byte(n >> 8), byte(n >> 16), byte(n >> 24), byte(n >> 32), byte(n >> 40), byte(n >> 48), byte(n >> 56), 0x01},
	}
}

// WFP built-in keys used for installing test filters.
var (
	fwpmLayerAleAuthConnectV4Key = windows.GUID{
		Data1: 0xc38d57d1,
		Data2: 0x05a7,
		Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}

	fwpmConditionIpRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a,
		Data2: 0x1d64,
		Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
	fwpmConditionIpRemotePort = windows.GUID{
		Data1: 0xc35a604d,
		Data2: 0xd22b,
		Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
	fwpmConditionIpProtocol = windows.GUID{
		Data1: 0x3971ef2b,
		Data2: 0x623e,
		Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
)

type fwpmProvider0 struct {
	ProviderKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        uint32
	ProviderData fwpByteBlob0
	ServiceName  *uint16
}

type fwpmSublayer0 struct {
	SubLayerKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        uint16
	_            uint16
	ProviderKey  *windows.GUID
	ProviderData fwpByteBlob0
	Weight       uint16
	_2           uint16
}

type fwpValue0 struct {
	Type uint32
	_    uint32
	// Union large enough for UINT64.
	Value uint64
}

type fwpmAction0 struct {
	Type uint32
	// Union in C; we only use simple action types.
	_ [16]byte
}

type fwpV4AddrMask struct {
	Addr uint32
	Mask uint32
}

type fwpmFilter0Full struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData0
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob0
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition0
	Action              fwpmAction0
	RawContext          uint64
	Reserved            *windows.GUID
	FilterId            uint64
	EffectiveWeight     fwpValue0
}

func requireWfpAdmin(t *testing.T) {
	t.Helper()

	var h uintptr
	ret, _, _ := procFwpmEngineOpen0.Call(
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&h)),
	)
	if ret != 0 {
		if uint32(ret) == uint32(windows.ERROR_ACCESS_DENIED) {
			t.Skip("requires Administrator / BFE access")
		}
		t.Fatalf("FwpmEngineOpen0 failed: 0x%x", ret)
	}
	defer procFwpmEngineClose0.Call(h)

	if err := enableWfpNetEvents(h); err != nil {
		// If we cannot enable net events, there is nothing meaningful to validate.
		if strings.Contains(strings.ToLower(err.Error()), "access denied") {
			t.Skip("requires Administrator / BFE access")
		}
		t.Skipf("unable to enable WFP net events: %v", err)
	}
}

func getNonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if ip4.IsLoopback() {
				continue
			}
			if !ip4.IsGlobalUnicast() {
				continue
			}
			return ip4
		}
	}
	return nil
}

func installZTAPTestFilter(t *testing.T, action uint32, remoteIP net.IP, remotePort uint16) {
	t.Helper()

	remoteIP4 := remoteIP.To4()
	if remoteIP4 == nil {
		t.Fatalf("expected IPv4 remote IP")
	}
	remote := uint32(remoteIP4[0])<<24 | uint32(remoteIP4[1])<<16 | uint32(remoteIP4[2])<<8 | uint32(remoteIP4[3])

	var h uintptr
	ret, _, _ := procFwpmEngineOpen0.Call(0, 0, 0, 0, uintptr(unsafe.Pointer(&h)))
	if ret != 0 {
		t.Fatalf("FwpmEngineOpen0 failed: 0x%x", ret)
	}
	defer procFwpmEngineClose0.Call(h)

	if err := enableWfpNetEvents(h); err != nil {
		t.Fatalf("enableWfpNetEvents: %v", err)
	}

	ret, _, _ = procFwpmTransactionBegin0.Call(h, 0)
	if ret != 0 {
		t.Fatalf("FwpmTransactionBegin0 failed: 0x%x", ret)
	}
	committed := false
	defer func() {
		if !committed {
			procFwpmTransactionAbort0.Call(h)
		}
	}()

	// Provider.
	provider := fwpmProvider0{
		ProviderKey:  ztapWFPProviderGUID,
		DisplayData:  fwpmDisplayData0{name: windows.StringToUTF16Ptr("ZTAP"), description: windows.StringToUTF16Ptr("ZTAP Test Provider")},
		Flags:        0,
		ProviderData: fwpByteBlob0{},
		ServiceName:  nil,
	}
	ret, _, _ = procFwpmProviderAdd0.Call(h, uintptr(unsafe.Pointer(&provider)), 0)
	if ret != 0 && ret != fwpEAlreadyExists {
		t.Fatalf("FwpmProviderAdd0 failed: 0x%x", ret)
	}

	// Sublayer.
	providerKey := ztapWFPProviderGUID
	sublayer := fwpmSublayer0{
		SubLayerKey:  ztapWFPSublayerGUID,
		DisplayData:  fwpmDisplayData0{name: windows.StringToUTF16Ptr("ZTAP Policies"), description: windows.StringToUTF16Ptr("ZTAP Test Sublayer")},
		Flags:        0,
		ProviderKey:  &providerKey,
		ProviderData: fwpByteBlob0{},
		Weight:       0xffff,
	}
	ret, _, _ = procFwpmSubLayerAdd0.Call(h, uintptr(unsafe.Pointer(&sublayer)), 0)
	if ret != 0 && ret != fwpEAlreadyExists {
		t.Fatalf("FwpmSubLayerAdd0 failed: 0x%x", ret)
	}

	// Cleanup any existing ZTAP filters.
	deleteFiltersByProvider(t, h, &ztapWFPProviderGUID)

	// Filter conditions.
	mask := fwpV4AddrMask{Addr: remote, Mask: 0xffffffff}
	conds := []fwpmFilterCondition0{
		{FieldKey: fwpmConditionIpRemoteAddress, MatchType: fwpMatchEqual, ConditionValue: fwpConditionValue0{Type: fwpDataTypeV4AddrMask, Value: uintptr(unsafe.Pointer(&mask))}},
		{FieldKey: fwpmConditionIpRemotePort, MatchType: fwpMatchEqual, ConditionValue: fwpConditionValue0{Type: fwpDataTypeUint16, Value: uintptr(remotePort)}},
		{FieldKey: fwpmConditionIpProtocol, MatchType: fwpMatchEqual, ConditionValue: fwpConditionValue0{Type: fwpDataTypeUint8, Value: uintptr(ProtocolTCP)}},
	}

	// Filter.
	f := fwpmFilter0Full{}
	f.FilterKey = newTestGUID()
	f.DisplayData.name = windows.StringToUTF16Ptr(fmt.Sprintf("ZTAP-Integration-%d", action))
	f.DisplayData.description = windows.StringToUTF16Ptr("ZTAP integration test filter")
	f.ProviderKey = &providerKey
	f.LayerKey = fwpmLayerAleAuthConnectV4Key
	f.SubLayerKey = ztapWFPSublayerGUID
	f.Weight.Type = fwpDataTypeUint64
	f.Weight.Value = 0xffffffffffffffff
	f.NumFilterConditions = uint32(len(conds))
	f.FilterCondition = &conds[0]
	f.Action.Type = action

	ret, _, _ = procFwpmFilterAdd0.Call(h, uintptr(unsafe.Pointer(&f)), 0, 0)
	if ret != 0 {
		t.Fatalf("FwpmFilterAdd0 failed: 0x%x", ret)
	}

	ret, _, _ = procFwpmTransactionCommit0.Call(h)
	if ret != 0 {
		t.Fatalf("FwpmTransactionCommit0 failed: 0x%x", ret)
	}
	committed = true
}

func deleteFiltersByProvider(t *testing.T, engine uintptr, providerKey *windows.GUID) {
	t.Helper()

	var enumHandle uintptr
	ret, _, _ := procFwpmFilterCreateEnumHandle0.Call(engine, 0, uintptr(unsafe.Pointer(&enumHandle)))
	if ret != 0 {
		t.Fatalf("FwpmFilterCreateEnumHandle0 failed: 0x%x", ret)
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(engine, enumHandle)

	for {
		var entries **fwpmFilter0Full
		var num uint32
		ret, _, _ = procFwpmFilterEnum0.Call(engine, enumHandle, 100, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&num)))
		if ret != 0 {
			t.Fatalf("FwpmFilterEnum0 failed: 0x%x", ret)
		}
		if num == 0 {
			break
		}
		filters := (*[1 << 20]*fwpmFilter0Full)(unsafe.Pointer(entries))[:num:num]
		for _, f := range filters {
			if f == nil || f.ProviderKey == nil {
				continue
			}
			if *f.ProviderKey != *providerKey {
				continue
			}
			ret, _, _ := procFwpmFilterDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(&f.FilterKey)))
			if ret != 0 && ret != fwpEFilterNotFound {
				t.Fatalf("FwpmFilterDeleteByKey0 failed: 0x%x", ret)
			}
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
	}
}

func waitForMatchingEvent(t *testing.T, ch <-chan RawFlowEvent, pred func(FlowEvent) bool, timeout time.Duration) FlowEvent {
	t.Helper()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	bootTime := time.Unix(0, 0)
	for {
		select {
		case <-deadline.C:
			t.Fatalf("timeout waiting for matching flow event")
		case raw := <-ch:
			fe := raw.ToFlowEvent(bootTime)
			if pred(fe) {
				return fe
			}
		}
	}
}

func waitForReaderSubscription(t *testing.T, r *WindowsReader, errCh <-chan error) {
	t.Helper()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()

	for {
		select {
		case err := <-errCh:
			// Start() only returns on stop/cancel; if it returns early, it failed.
			if err != nil {
				t.Fatalf("reader.Start failed: %v", err)
			}
			t.Fatalf("reader.Start returned unexpectedly")
		case <-deadline.C:
			t.Fatalf("timeout waiting for reader subscription")
		default:
			r.mu.RLock()
			ver := r.subscribeVersion
			r.mu.RUnlock()
			if ver >= 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func deleteFiltersByProviderBestEffort(engine uintptr, providerKey *windows.GUID) error {
	var enumHandle uintptr
	ret, _, _ := procFwpmFilterCreateEnumHandle0.Call(engine, 0, uintptr(unsafe.Pointer(&enumHandle)))
	if ret != 0 {
		return fmt.Errorf("FwpmFilterCreateEnumHandle0 failed: 0x%x", ret)
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(engine, enumHandle)

	for {
		var entries **fwpmFilter0Full
		var num uint32
		ret, _, _ = procFwpmFilterEnum0.Call(engine, enumHandle, 100, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&num)))
		if ret != 0 {
			return fmt.Errorf("FwpmFilterEnum0 failed: 0x%x", ret)
		}
		if num == 0 {
			break
		}
		filters := (*[1 << 20]*fwpmFilter0Full)(unsafe.Pointer(entries))[:num:num]
		for _, f := range filters {
			if f == nil || f.ProviderKey == nil {
				continue
			}
			if *f.ProviderKey != *providerKey {
				continue
			}
			procFwpmFilterDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(&f.FilterKey)))
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
	}
	return nil
}

func TestWFPFlowIntegration_AllowedEgress(t *testing.T) {
	requireWfpAdmin(t)

	ip := getNonLoopbackIPv4(t)
	if ip == nil {
		t.Skip("no non-loopback IPv4 address found")
	}

	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		c, _ := ln.AcceptTCP()
		if c != nil {
			c.Close()
		}
	}()

	installZTAPTestFilter(t, fwpActionPermit, ip, port)
	defer func() {
		// Best-effort cleanup.
		var h uintptr
		ret, _, _ := procFwpmEngineOpen0.Call(0, 0, 0, 0, uintptr(unsafe.Pointer(&h)))
		if ret == 0 {
			procFwpmTransactionBegin0.Call(h, 0)
			_ = deleteFiltersByProviderBestEffort(h, &ztapWFPProviderGUID)
			procFwpmTransactionCommit0.Call(h)
			procFwpmEngineClose0.Call(h)
		}
	}()

	reader := NewWindowsReader()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan RawFlowEvent, 4096)
	errCh := make(chan error, 1)
	go func() { errCh <- reader.Start(ctx, out) }()
	waitForReaderSubscription(t, reader, errCh)
	defer reader.Stop()

	time.Sleep(200 * time.Millisecond)

	// Generate matching traffic.
	conn, _ := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", ip.String(), port), 2*time.Second)
	if conn != nil {
		conn.Close()
	}

	fe := waitForMatchingEvent(t, out, func(ev FlowEvent) bool {
		return ev.Action == "allowed" && ev.Direction == "egress" && ev.Protocol == "TCP" && ev.DestPort == port && ev.DestIP.Equal(ip)
	}, 5*time.Second)

	if fe.DestPort != port {
		t.Fatalf("DestPort=%d want %d", fe.DestPort, port)
	}
}

func TestWFPFlowIntegration_BlockedEgress(t *testing.T) {
	requireWfpAdmin(t)

	ip := getNonLoopbackIPv4(t)
	if ip == nil {
		t.Skip("no non-loopback IPv4 address found")
	}

	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		c, _ := ln.AcceptTCP()
		if c != nil {
			c.Close()
		}
	}()

	installZTAPTestFilter(t, fwpActionBlock, ip, port)
	defer func() {
		var h uintptr
		ret, _, _ := procFwpmEngineOpen0.Call(0, 0, 0, 0, uintptr(unsafe.Pointer(&h)))
		if ret == 0 {
			procFwpmTransactionBegin0.Call(h, 0)
			_ = deleteFiltersByProviderBestEffort(h, &ztapWFPProviderGUID)
			procFwpmTransactionCommit0.Call(h)
			procFwpmEngineClose0.Call(h)
		}
	}()

	reader := NewWindowsReader()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan RawFlowEvent, 4096)
	errCh := make(chan error, 1)
	go func() { errCh <- reader.Start(ctx, out) }()
	waitForReaderSubscription(t, reader, errCh)
	defer reader.Stop()

	time.Sleep(200 * time.Millisecond)

	// Generate matching traffic; it should be blocked.
	conn, _ := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", ip.String(), port), 2*time.Second)
	if conn != nil {
		conn.Close()
	}

	fe := waitForMatchingEvent(t, out, func(ev FlowEvent) bool {
		return ev.Action == "blocked" && ev.Direction == "egress" && ev.Protocol == "TCP" && ev.DestPort == port && ev.DestIP.Equal(ip)
	}, 5*time.Second)

	if fe.DestPort != port {
		t.Fatalf("DestPort=%d want %d", fe.DestPort, port)
	}
}
