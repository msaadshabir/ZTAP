//go:build windows

package flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"ztap/pkg/logging"

	"golang.org/x/sys/windows"
)

var (
	modfwpuclnt = syscall.NewLazyDLL("fwpuclnt.dll")

	procFwpmEngineOpen0  = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0 = modfwpuclnt.NewProc("FwpmEngineClose0")

	procFwpmNetEventSubscribe0   = modfwpuclnt.NewProc("FwpmNetEventSubscribe0")
	procFwpmNetEventSubscribe1   = modfwpuclnt.NewProc("FwpmNetEventSubscribe1")
	procFwpmNetEventSubscribe2   = modfwpuclnt.NewProc("FwpmNetEventSubscribe2")
	procFwpmNetEventUnsubscribe0 = modfwpuclnt.NewProc("FwpmNetEventUnsubscribe0")
)

// WindowsReader reads flow events from WFP NetEvents on Windows.
type WindowsReader struct {
	mu          sync.RWMutex
	running     bool
	stopCh      chan struct{}
	doneCh      chan struct{}
	cleanupOnce sync.Once

	engineHandle uintptr
	subHandle    uintptr
	eventCh      chan<- RawFlowEvent
	callback0    uintptr
	callback1    uintptr
	callback2    uintptr
}

// NewWindowsReader creates a new Windows flow reader.
func NewWindowsReader() *WindowsReader {
	return &WindowsReader{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Start begins reading flow events from WFP.
func (r *WindowsReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	// Reset per-run state.
	r.running = true
	r.cleanupOnce = sync.Once{}
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	r.engineHandle = 0
	r.subHandle = 0
	r.eventCh = eventCh
	r.callback0 = 0
	r.callback1 = 0
	r.callback2 = 0
	stopCh := r.stopCh
	doneCh := r.doneCh
	r.mu.Unlock()

	defer func() {
		_ = r.cleanup()
		close(doneCh)
	}()

	if err := r.openEngine(); err != nil {
		return err
	}

	if err := r.subscribe(); err != nil {
		return err
	}

	runtime.KeepAlive(r)
	logging.Info("Windows flow reader started (WFP NetEvents)", nil)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopCh:
		return nil
	}
}

// Stop stops the reader.
func (r *WindowsReader) Stop() error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	stopCh := r.stopCh
	doneCh := r.doneCh
	r.mu.Unlock()

	select {
	case <-stopCh:
		// Already closed.
	default:
		close(stopCh)
	}

	// Wait for Start() to unwind and cleanup.
	<-doneCh
	return nil
}

// Available returns true if the reader can be used on this platform.
func (r *WindowsReader) Available() bool {
	return true
}

// ---- WFP NetEvent types (partial, but layout-accurate) ----

// FWP_IP_VERSION values.
const (
	fwpIPVersionV4 uint32 = 0
	fwpIPVersionV6 uint32 = 1
)

// FWPM_NET_EVENT_TYPE values.
const (
	fwpmNetEventTypeIkeMmFailure     uint32 = 0
	fwpmNetEventTypeIkeQmFailure     uint32 = 1
	fwpmNetEventTypeIkeEmFailure     uint32 = 2
	fwpmNetEventTypeClassifyDrop     uint32 = 3
	fwpmNetEventTypeIPsecKernelDrop  uint32 = 4
	fwpmNetEventTypeIPsecDospDrop    uint32 = 5
	fwpmNetEventTypeClassifyAllow    uint32 = 6
	fwpmNetEventTypeCapabilityDrop   uint32 = 7
	fwpmNetEventTypeCapabilityAllow  uint32 = 8
	fwpmNetEventTypeClassifyDropMac  uint32 = 9
	fwpmNetEventTypeLpmPacketArrival uint32 = 10
)

// FWP_DIRECTION values (msFwpDirection).
const (
	fwpDirectionIn      uint32 = 0x00003900
	fwpDirectionOut     uint32 = 0x00003901
	fwpDirectionForward uint32 = 0x00003902
)

type fwpByteBlob struct {
	Size uint32
	Data uintptr
}

type fwpmNetEventSubscription0 struct {
	EnumTemplate uintptr // FWPM_NET_EVENT_ENUM_TEMPLATE0*
	Flags        uint32
	SessionKey   windows.GUID
}

// Common prefix across FWPM_NET_EVENT_HEADER0/2/3.
type fwpmNetEventHeaderPrefix struct {
	TimeStamp windows.Filetime
	Flags     uint32
	IPVersion uint32
	IPProto   uint8
	_         [3]byte
	LocalAddr [16]byte
	RemoteAddr [16]byte
	LocalPort uint16
	RemotePort uint16
	ScopeId   uint32
}

type fwpmNetEventHeader2 struct {
	Prefix        fwpmNetEventHeaderPrefix
	AppId         fwpByteBlob
	UserId        uintptr
	AddressFamily uint32 // FWP_AF (enum)
	PackageSid    uintptr
}

// FWPM_NET_EVENT_HEADER0 (Windows Vista/7).
type fwpmNetEventHeader0 struct {
	Prefix fwpmNetEventHeaderPrefix
	AppId  fwpByteBlob
	UserId uintptr
}

// FWPM_NET_EVENT0 (Windows Vista/7) used by Subscribe0.
type fwpmNetEvent0 struct {
	Header fwpmNetEventHeader0
	Type   uint32
	_      uint32
	Data   uintptr
}

type fwpmNetEventHeader3 struct {
	Header2      fwpmNetEventHeader2
	EnterpriseId uintptr
	PolicyFlags  uint64
	EffectiveName fwpByteBlob
}

// FWPM_NET_EVENT2 (Windows 8+) used by Subscribe1.
type fwpmNetEvent2 struct {
	Header fwpmNetEventHeader2
	Type   uint32
	_      uint32
	Data   uintptr
}

// FWPM_NET_EVENT3 (Windows 10 1607+) used by Subscribe2.
type fwpmNetEvent3 struct {
	Header fwpmNetEventHeader3
	Type   uint32
	_      uint32
	Data   uintptr
}

// Enough of FWPM_NET_EVENT_CLASSIFY_ALLOW0 for direction extraction.
type fwpmNetEventClassifyAllow0 struct {
	FilterId        uint64
	LayerId         uint16
	_               uint16
	ReauthReason    uint32
	OriginalProfile uint32
	CurrentProfile  uint32
	MsFwpDirection  uint32
	IsLoopback      int32 // BOOL
}

// Compatible with FWPM_NET_EVENT_CLASSIFY_DROP1 and prefix of DROP2.
type fwpmNetEventClassifyDrop1 struct {
	FilterId        uint64
	LayerId         uint16
	_               uint16
	ReauthReason    uint32
	OriginalProfile uint32
	CurrentProfile  uint32
	MsFwpDirection  uint32
	IsLoopback      int32 // BOOL
}

// ---- Reader implementation ----

func (r *WindowsReader) openEngine() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.engineHandle != 0 {
		return nil
	}

	var handle uintptr
	// FwpmEngineOpen0(
	//   serverName, authnService, authIdentity, session, engineHandle
	// )
	ret, _, _ := procFwpmEngineOpen0.Call(
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed with error 0x%x", ret)
	}

	r.engineHandle = handle
	return nil
}

func (r *WindowsReader) subscribe() error {
	r.mu.RLock()
	h := r.engineHandle
	r.mu.RUnlock()
	if h == 0 {
		return fmt.Errorf("WFP engine handle is not open")
	}

	var sub fwpmNetEventSubscription0
	sub.EnumTemplate = 0 // match all
	// flags unused

	var eventsHandle uintptr

	// Prefer Subscribe2 (NetEvent3), fallback to Subscribe1 (NetEvent2), finally Subscribe0.
	// Even if a proc is present, the call can still fail; try fallbacks before giving up.
	var subscribeErr error
	if err := procFwpmNetEventSubscribe2.Find(); err == nil {
		cb := syscall.NewCallback(wfpNetEventCallback2)
		ret, _, _ := procFwpmNetEventSubscribe2.Call(
			h,
			uintptr(unsafe.Pointer(&sub)),
			cb,
			uintptr(unsafe.Pointer(r)),
			uintptr(unsafe.Pointer(&eventsHandle)),
		)
		if ret == 0 {
			r.mu.Lock()
			r.subHandle = eventsHandle
			r.callback2 = cb
			r.mu.Unlock()
			return nil
		}
		subscribeErr = fmt.Errorf("FwpmNetEventSubscribe2 failed with error 0x%x", ret)
	}

	if err := procFwpmNetEventSubscribe1.Find(); err == nil {
		cb := syscall.NewCallback(wfpNetEventCallback1)
		ret, _, _ := procFwpmNetEventSubscribe1.Call(
			h,
			uintptr(unsafe.Pointer(&sub)),
			cb,
			uintptr(unsafe.Pointer(r)),
			uintptr(unsafe.Pointer(&eventsHandle)),
		)
		if ret == 0 {
			r.mu.Lock()
			r.subHandle = eventsHandle
			r.callback1 = cb
			r.mu.Unlock()
			return nil
		}
		if subscribeErr == nil {
			subscribeErr = fmt.Errorf("FwpmNetEventSubscribe1 failed with error 0x%x", ret)
		}
	}

	if err := procFwpmNetEventSubscribe0.Find(); err != nil {
		if subscribeErr != nil {
			return subscribeErr
		}
		return fmt.Errorf("no supported net event subscribe function available: %w", err)
	}
	cb := syscall.NewCallback(wfpNetEventCallback0)
	ret, _, _ := procFwpmNetEventSubscribe0.Call(
		h,
		uintptr(unsafe.Pointer(&sub)),
		cb,
		uintptr(unsafe.Pointer(r)),
		uintptr(unsafe.Pointer(&eventsHandle)),
	)
	if ret != 0 {
		if subscribeErr != nil {
			return subscribeErr
		}
		return fmt.Errorf("FwpmNetEventSubscribe0 failed with error 0x%x", ret)
	}
	r.mu.Lock()
	r.subHandle = eventsHandle
	r.callback0 = cb
	r.mu.Unlock()
	return nil
}

func (r *WindowsReader) cleanup() error {
	var errOut error
	r.cleanupOnce.Do(func() {
		r.mu.RLock()
		engine := r.engineHandle
		sub := r.subHandle
		r.mu.RUnlock()

		if engine != 0 && sub != 0 {
			ret, _, _ := procFwpmNetEventUnsubscribe0.Call(engine, sub)
			if ret != 0 {
				errOut = fmt.Errorf("FwpmNetEventUnsubscribe0 failed with error 0x%x", ret)
			}
		}

		if engine != 0 {
			ret, _, _ := procFwpmEngineClose0.Call(engine)
			if ret != 0 && errOut == nil {
				errOut = fmt.Errorf("FwpmEngineClose0 failed with error 0x%x", ret)
			}
		}

		r.mu.Lock()
		r.engineHandle = 0
		r.subHandle = 0
		r.eventCh = nil
		r.callback0 = 0
		r.callback1 = 0
		r.callback2 = 0
		r.running = false
		r.mu.Unlock()
	})

	return errOut
}

func wfpNetEventCallback0(ctx, event uintptr) uintptr {
	r := (*WindowsReader)(unsafe.Pointer(ctx))
	if r == nil {
		return 0
	}
	r.handleNetEvent0((*fwpmNetEvent0)(unsafe.Pointer(event)))
	return 0
}

func wfpNetEventCallback1(ctx, event uintptr) uintptr {
	r := (*WindowsReader)(unsafe.Pointer(ctx))
	if r == nil {
		return 0
	}
	r.handleNetEvent2((*fwpmNetEvent2)(unsafe.Pointer(event)))
	return 0
}

func wfpNetEventCallback2(ctx, event uintptr) uintptr {
	r := (*WindowsReader)(unsafe.Pointer(ctx))
	if r == nil {
		return 0
	}
	r.handleNetEvent3((*fwpmNetEvent3)(unsafe.Pointer(event)))
	return 0
}

func (r *WindowsReader) handleNetEvent2(ev *fwpmNetEvent2) {
	raw, ok := wfpNetEvent2ToRawFlowEvent(ev)
	if !ok {
		return
	}
	// Use uptime (ns since boot) as timestamp.
	ns := uptimeNsFunc()
	if ns < 0 {
		ns = 0
	}
	raw.TimestampNs = uint64(ns) // #nosec G115 -- ns is clamped to >=0 above

	r.mu.RLock()
	ch := r.eventCh
	r.mu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- raw:
	default:
	}
}

func (r *WindowsReader) handleNetEvent0(ev *fwpmNetEvent0) {
	if ev == nil {
		return
	}
	// Best-effort: FWPM_NET_EVENT0 doesn't include msFwpDirection.
	if ev.Type != fwpmNetEventTypeClassifyDrop {
		return
	}

	var family uint8
	var localIP [4]uint32
	var remoteIP [4]uint32

	switch ev.Header.Prefix.IPVersion {
	case fwpIPVersionV4:
		family = 4
		localIP[0] = binary.BigEndian.Uint32(ev.Header.Prefix.LocalAddr[:4])
		remoteIP[0] = binary.BigEndian.Uint32(ev.Header.Prefix.RemoteAddr[:4])
	case fwpIPVersionV6:
		family = 6
		for i := 0; i < 4; i++ {
			localIP[i] = binary.LittleEndian.Uint32(ev.Header.Prefix.LocalAddr[i*4 : i*4+4])
			remoteIP[i] = binary.LittleEndian.Uint32(ev.Header.Prefix.RemoteAddr[i*4 : i*4+4])
		}
	default:
		return
	}

	ns := uptimeNsFunc()
	if ns < 0 {
		ns = 0
	}

	raw := RawFlowEvent{
		TimestampNs: uint64(ns), // #nosec G115 -- ns is clamped to >=0 above
		SrcIP:       localIP,
		DestIP:      remoteIP,
		SrcPort:     ev.Header.Prefix.LocalPort,
		DestPort:    ev.Header.Prefix.RemotePort,
		Protocol:    ev.Header.Prefix.IPProto,
		Direction:   DirectionEgress,
		Action:      ActionBlocked,
		Family:      family,
	}

	r.mu.RLock()
	ch := r.eventCh
	r.mu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- raw:
	default:
	}
}

func (r *WindowsReader) handleNetEvent3(ev *fwpmNetEvent3) {
	raw, ok := wfpNetEvent3ToRawFlowEvent(ev)
	if !ok {
		return
	}
	ns := uptimeNsFunc()
	if ns < 0 {
		ns = 0
	}
	raw.TimestampNs = uint64(ns) // #nosec G115 -- ns is clamped to >=0 above

	r.mu.RLock()
	ch := r.eventCh
	r.mu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- raw:
	default:
	}
}

func wfpNetEvent2ToRawFlowEvent(ev *fwpmNetEvent2) (RawFlowEvent, bool) {
	if ev == nil {
		return RawFlowEvent{}, false
	}
	return wfpHeaderAndTypeToRaw(&ev.Header.Prefix, ev.Type, ev.Data)
}

func wfpNetEvent3ToRawFlowEvent(ev *fwpmNetEvent3) (RawFlowEvent, bool) {
	if ev == nil {
		return RawFlowEvent{}, false
	}
	return wfpHeaderAndTypeToRaw(&ev.Header.Header2.Prefix, ev.Type, ev.Data)
}

func wfpHeaderAndTypeToRaw(prefix *fwpmNetEventHeaderPrefix, typ uint32, data uintptr) (RawFlowEvent, bool) {
	if prefix == nil {
		return RawFlowEvent{}, false
	}

	var action uint8
	var dir uint8

	switch typ {
	case fwpmNetEventTypeClassifyAllow:
		action = ActionAllowed
		allow := (*fwpmNetEventClassifyAllow0)(unsafe.Pointer(data))
		dir = msDirectionToFlowDirection(allow)
	case fwpmNetEventTypeClassifyDrop:
		action = ActionBlocked
		drop := (*fwpmNetEventClassifyDrop1)(unsafe.Pointer(data))
		dir = msDirectionToFlowDirection(drop)
	default:
		return RawFlowEvent{}, false
	}

	family := uint8(0)
	var localIP [4]uint32
	var remoteIP [4]uint32

	switch prefix.IPVersion {
	case fwpIPVersionV4:
		family = 4
		localIP[0] = binary.BigEndian.Uint32(prefix.LocalAddr[:4])
		remoteIP[0] = binary.BigEndian.Uint32(prefix.RemoteAddr[:4])
	case fwpIPVersionV6:
		family = 6
		for i := 0; i < 4; i++ {
			localIP[i] = binary.LittleEndian.Uint32(prefix.LocalAddr[i*4 : i*4+4])
			remoteIP[i] = binary.LittleEndian.Uint32(prefix.RemoteAddr[i*4 : i*4+4])
		}
	default:
		return RawFlowEvent{}, false
	}

	localPort := prefix.LocalPort
	remotePort := prefix.RemotePort
	proto := prefix.IPProto

	// Apply direction to decide which endpoint is source/destination.
	if dir == DirectionIngress {
		return RawFlowEvent{
			SrcIP:     remoteIP,
			DestIP:    localIP,
			SrcPort:   remotePort,
			DestPort:  localPort,
			Protocol:  proto,
			Direction: DirectionIngress,
			Action:    action,
			Family:    family,
		}, true
	}

	return RawFlowEvent{
		SrcIP:     localIP,
		DestIP:    remoteIP,
		SrcPort:   localPort,
		DestPort:  remotePort,
		Protocol:  proto,
		Direction: DirectionEgress,
		Action:    action,
		Family:    family,
	}, true
}

type hasMsDirection interface{
	msDir() uint32
}

func (c *fwpmNetEventClassifyAllow0) msDir() uint32 {
	if c == nil {
		return 0
	}
	return c.MsFwpDirection
}

func (c *fwpmNetEventClassifyDrop1) msDir() uint32 {
	if c == nil {
		return 0
	}
	return c.MsFwpDirection
}

func msDirectionToFlowDirection(v hasMsDirection) uint8 {
	switch v.msDir() {
	case fwpDirectionIn:
		return DirectionIngress
	case fwpDirectionOut:
		return DirectionEgress
	default:
		// Best-effort default.
		return DirectionEgress
	}
}
