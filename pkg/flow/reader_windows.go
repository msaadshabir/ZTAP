//go:build windows

package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"ztap/pkg/logging"

	"golang.org/x/sys/windows"
)

var (
	modfwpuclnt = syscall.NewLazyDLL("fwpuclnt.dll")

	procFwpmEngineOpen0      = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0     = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmEngineSetOption0 = modfwpuclnt.NewProc("FwpmEngineSetOption0")

	procFwpmNetEventSubscribe0   = modfwpuclnt.NewProc("FwpmNetEventSubscribe0")
	procFwpmNetEventSubscribe1   = modfwpuclnt.NewProc("FwpmNetEventSubscribe1")
	procFwpmNetEventSubscribe2   = modfwpuclnt.NewProc("FwpmNetEventSubscribe2")
	procFwpmNetEventUnsubscribe0 = modfwpuclnt.NewProc("FwpmNetEventUnsubscribe0")
)

const (
	fwpmEngineCollectNetEvents uint32 = 0
)

// WindowsReader reads flow events from WFP NetEvents on Windows.
type WindowsReader struct {
	mu          sync.RWMutex
	running     bool
	stopCh      chan struct{}
	doneCh      chan struct{}
	cleanupOnce sync.Once

	// Configuration.
	ztapOnly bool

	// Effective configuration for the current run.
	ztapOnlyEffective bool

	// Internal pipeline.
	inCh        chan wfpEvent
	filterCache *filterOwnerCache
	deduper     *wfpDeduper
	layerCache  *layerKeyCache

	// WFP subscription state.
	// We may create multiple subscriptions (e.g. allow + drop).
	subHandles        [2]uintptr
	netEventTemplates [2]*wfpNetEventTemplate

	// Subscription version in use: 2 (Win10 1607+), 1 (Win8+), 0 (Win7).
	subscribeVersion int

	// Telemetry.
	droppedInCh        atomic.Uint64
	filterLookupErrors atomic.Uint64
	unknownDirection   atomic.Uint64
	allowSeen          atomic.Uint64
	dropSeen           atomic.Uint64
	warnedNoAllow      atomic.Uint32

	engineHandle uintptr
	eventCh      chan<- RawFlowEvent
	callback0    uintptr
	callback1    uintptr
	callback2    uintptr
}

// wfpEvent is a Go-owned copy of the minimal net event fields we need.
//
// The WFP callback-provided memory is only valid during the callback, so we
// must copy anything we want to use asynchronously.
type wfpEvent struct {
	typ      uint32
	filterID uint64
	layerID  uint16
	msDir    uint32

	ipVersion  uint32
	proto      uint8
	localAddr  [16]byte
	remoteAddr [16]byte
	localPort  uint16
	remotePort uint16
}

// NewWindowsReader creates a new Windows flow reader.
func NewWindowsReader() *WindowsReader {
	return &WindowsReader{
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		ztapOnly:    true,
		filterCache: newFilterOwnerCache(8192),
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
	r.subHandles = [2]uintptr{}
	r.netEventTemplates = [2]*wfpNetEventTemplate{}
	r.eventCh = eventCh
	r.inCh = make(chan wfpEvent, 8192)
	r.deduper = newWfpDeduper(10000, 250_000_000) // 10k keys, 250ms window
	r.layerCache = newLayerKeyCache()
	r.callback0 = 0
	r.callback1 = 0
	r.callback2 = 0
	r.subscribeVersion = -1
	r.droppedInCh.Store(0)
	r.filterLookupErrors.Store(0)
	r.unknownDirection.Store(0)
	r.allowSeen.Store(0)
	r.dropSeen.Store(0)
	r.warnedNoAllow.Store(0)
	r.ztapOnlyEffective = r.ztapOnly
	stopCh := r.stopCh
	doneCh := r.doneCh
	inCh := r.inCh
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

	r.mu.RLock()
	ver := r.subscribeVersion
	ztapOnly := r.ztapOnlyEffective
	r.mu.RUnlock()

	if ver == 0 && ztapOnly {
		logging.Warn("WFP NetEvents subscribe0 does not include enough metadata for ztap-only mode; falling back to all events", nil)
		ztapOnly = false
		r.mu.Lock()
		r.ztapOnlyEffective = false
		r.mu.Unlock()
	}

	go r.runWorker(ctx, stopCh, inCh, ztapOnly)
	go r.warnIfNoAllow(ctx, stopCh)

	r.mu.RLock()
	ver = r.subscribeVersion
	ztapOnly = r.ztapOnlyEffective
	subs := r.subHandles
	r.mu.RUnlock()
	mode := "ztap-only"
	if !ztapOnly {
		mode = "all"
	}
	types := ""
	if subs[netEventSubAllow] != 0 {
		types = "allow"
	}
	if subs[netEventSubDrop] != 0 {
		if types != "" {
			types += ","
		}
		types += "drop"
	}
	if types == "" {
		types = "none"
	}
	logging.Infof("Windows flow reader started (WFP NetEvents, mode=%s, api=subscribe%d, types=%s)", mode, ver, types)
	if ver >= 1 && subs[netEventSubAllow] == 0 {
		logging.Warn("WFP NetEvents allow subscription is not active; you may only see drops", nil)
	}

	runtime.KeepAlive(r)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopCh:
		return nil
	}
}

func (r *WindowsReader) runWorker(ctx context.Context, stopCh <-chan struct{}, inCh <-chan wfpEvent, ztapOnly bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case ev, ok := <-inCh:
			if !ok {
				return
			}

			if ztapOnly {
				isZTAP, err := r.isZTAPFilter(ev.filterID)
				if err != nil {
					n := r.filterLookupErrors.Add(1)
					if n == 1 || n%10000 == 0 {
						logging.Warnf("WFP filter correlation failed; dropping events in ztap-only mode: errors=%d last_error=%v", n, err)
					}
					continue
				}
				if !isZTAP {
					continue
				}
			}

			raw, ok := r.wfpEventToRawFlowEvent(ev)
			if !ok {
				continue
			}

			switch raw.Action {
			case ActionAllowed:
				r.allowSeen.Add(1)
			case ActionBlocked:
				r.dropSeen.Add(1)
			}

			// Use uptime (ns since boot) as timestamp.
			ns := uptimeNsFunc()
			if ns < 0 {
				ns = 0
			}
			ts := uint64(ns) // #nosec G115 -- ns is clamped to >=0 above

			// Deduplicate near-identical events (common when multiple layers fire).
			if r.deduper != nil {
				if r.deduper.SeenRecently(wfpDedupKeyFrom(ev, raw), ts) {
					continue
				}
			}

			raw.TimestampNs = ts

			r.mu.RLock()
			out := r.eventCh
			r.mu.RUnlock()
			if out == nil {
				continue
			}
			select {
			case out <- raw:
			default:
			}
		}
	}
}

func (r *WindowsReader) warnIfNoAllow(ctx context.Context, stopCh <-chan struct{}) {
	if r == nil {
		return
	}

	r.mu.RLock()
	ver := r.subscribeVersion
	subs := r.subHandles
	r.mu.RUnlock()
	if ver < 1 {
		return
	}
	if subs[netEventSubAllow] == 0 {
		return
	}

	select {
	case <-ctx.Done():
		return
	case <-stopCh:
		return
	case <-time.After(2 * time.Second):
	}

	allows := r.allowSeen.Load()
	drops := r.dropSeen.Load()
	if allows == 0 && drops > 0 {
		if r.warnedNoAllow.CompareAndSwap(0, 1) {
			logging.Warn("WFP allow events not observed (drops seen); if you expect allowed-flow visibility, verify WFP net event logging/auditing is enabled", nil)
		}
	}
}

func formatWfpCallError(name string, ret uintptr) error {
	code := uint32(ret)
	if code == uint32(windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%s failed: access denied (run as Administrator / ensure BFE access)", name)
	}
	return fmt.Errorf("%s failed with error 0x%x", name, ret)
}

func (r *WindowsReader) wfpEventToRawFlowEvent(ev wfpEvent) (RawFlowEvent, bool) {
	var action uint8
	switch ev.typ {
	case fwpmNetEventTypeClassifyAllow, fwpmNetEventTypeCapabilityAllow:
		action = ActionAllowed
	case fwpmNetEventTypeClassifyDrop, fwpmNetEventTypeCapabilityDrop:
		action = ActionBlocked
	default:
		return RawFlowEvent{}, false
	}

	dir, ok := msDirectionValueToFlowDirection(ev.msDir)
	if !ok {
		if r != nil {
			if key, found, err := r.layerKeyByID(ev.layerID); err == nil && found {
				if inferred, ok2 := inferDirectionFromLayerKey(key); ok2 {
					dir, ok = inferred, true
				}
			}
		}
	}
	if !ok {
		if r != nil {
			n := r.unknownDirection.Add(1)
			if n == 1 || n%10000 == 0 {
				logging.Warnf("unable to determine WFP event direction; defaulting to egress: count=%d ms_dir=0x%x layer_id=%d", n, ev.msDir, ev.layerID)
			}
		}
		dir = DirectionEgress
	}

	family := uint8(0)
	var localIP [4]uint32
	var remoteIP [4]uint32

	switch ev.ipVersion {
	case fwpIPVersionV4:
		family = 4
		localIP[0] = binary.BigEndian.Uint32(ev.localAddr[:4])
		remoteIP[0] = binary.BigEndian.Uint32(ev.remoteAddr[:4])
	case fwpIPVersionV6:
		family = 6
		for i := 0; i < 4; i++ {
			localIP[i] = binary.LittleEndian.Uint32(ev.localAddr[i*4 : i*4+4])
			remoteIP[i] = binary.LittleEndian.Uint32(ev.remoteAddr[i*4 : i*4+4])
		}
	default:
		return RawFlowEvent{}, false
	}

	localPort := ev.localPort
	remotePort := ev.remotePort
	proto := ev.proto

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

func msDirectionValueToFlowDirection(msDir uint32) (uint8, bool) {
	switch msDir {
	case fwpDirectionIn:
		return DirectionIngress, true
	case fwpDirectionOut:
		return DirectionEgress, true
	case fwpDirectionForward:
		// Best-effort: treat forward as egress.
		return DirectionEgress, true
	default:
		return 0, false
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

// Minimal structures for filtering net event subscriptions.
//
// Notes:
// - FWPM_NET_EVENT_ENUM_TEMPLATE0 supports filter conditions, but they are
//   AND'ed; to filter for both allow and drop we create two subscriptions.
// - We keep these in Go-managed memory and store pointers on WindowsReader so
//   they remain alive until we unsubscribe.

const (
	fwpMatchEqual     uint32 = 0
	fwpDataTypeUint32 uint32 = 3
)

const (
	netEventSubDrop = iota
	netEventSubAllow
)

var fwpmConditionNetEventType = windows.GUID{
	Data1: 0x206e9996,
	Data2: 0x490e,
	Data3: 0x40cf,
	Data4: [8]byte{0xb8, 0x31, 0xb3, 0x86, 0x41, 0xeb, 0x6f, 0xcb},
}

type fwpConditionValue0 struct {
	Type uint32
	_    uint32
	// Union; for FWP_UINT32 it is stored inline in the low 32-bits.
	Value uintptr
}

type fwpmFilterCondition0 struct {
	FieldKey       windows.GUID
	MatchType      uint32
	ConditionValue fwpConditionValue0
}

type fwpmNetEventEnumTemplate0 struct {
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition0
}

type wfpNetEventTemplate struct {
	enum fwpmNetEventEnumTemplate0
	cond fwpmFilterCondition0
}

func newNetEventTypeTemplate(typ uint32) *wfpNetEventTemplate {
	t := &wfpNetEventTemplate{}
	t.cond.FieldKey = fwpmConditionNetEventType
	t.cond.MatchType = fwpMatchEqual
	t.cond.ConditionValue.Type = fwpDataTypeUint32
	t.cond.ConditionValue.Value = uintptr(typ)

	t.enum.NumFilterConditions = 1
	t.enum.FilterCondition = &t.cond
	return t
}

// Common prefix across FWPM_NET_EVENT_HEADER0/2/3.
type fwpmNetEventHeaderPrefix struct {
	TimeStamp  windows.Filetime
	Flags      uint32
	IPVersion  uint32
	IPProto    uint8
	_          [3]byte
	LocalAddr  [16]byte
	RemoteAddr [16]byte
	LocalPort  uint16
	RemotePort uint16
	ScopeId    uint32
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

// Enough of FWPM_NET_EVENT_CLASSIFY_DROP0 for FilterId/LayerId extraction.
//
// Used by older net event callbacks that do not include msFwpDirection.
type fwpmNetEventClassifyDrop0 struct {
	FilterId uint64
	LayerId  uint16
	_        uint16
}

type fwpmNetEventHeader3 struct {
	Header2       fwpmNetEventHeader2
	EnterpriseId  uintptr
	PolicyFlags   uint64
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
		return formatWfpCallError("FwpmEngineOpen0", ret)
	}

	// Ensure net event collection is enabled.
	if err := enableWfpNetEvents(handle); err != nil {
		procFwpmEngineClose0.Call(handle)
		return err
	}

	r.engineHandle = handle
	return nil
}

func enableWfpNetEvents(engine uintptr) error {
	// FWPM_ENGINE_COLLECT_NET_EVENTS expects a UINT32 0/1.
	var on uint32 = 1
	ret, _, _ := procFwpmEngineSetOption0.Call(
		engine,
		uintptr(fwpmEngineCollectNetEvents),
		uintptr(unsafe.Pointer(&on)),
	)
	if ret != 0 {
		return formatWfpCallError("FwpmEngineSetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS)", ret)
	}
	return nil
}

func (r *WindowsReader) subscribe() error {
	r.mu.RLock()
	h := r.engineHandle
	r.mu.RUnlock()
	if h == 0 {
		return errors.New("WFP engine handle is not open")
	}

	// Net event type filtering: create a subscription per type (conditions are AND'ed).
	dropTmpl := newNetEventTypeTemplate(fwpmNetEventTypeClassifyDrop)
	allowTmpl := newNetEventTypeTemplate(fwpmNetEventTypeClassifyAllow)

	subscribeOne := func(proc *syscall.LazyProc, cb uintptr, tmpl *wfpNetEventTemplate, idx int) error {
		var eventsHandle uintptr
		var sub fwpmNetEventSubscription0
		sub.EnumTemplate = uintptr(unsafe.Pointer(&tmpl.enum))
		ret, _, _ := proc.Call(
			h,
			uintptr(unsafe.Pointer(&sub)),
			cb,
			uintptr(unsafe.Pointer(r)),
			uintptr(unsafe.Pointer(&eventsHandle)),
		)
		if ret != 0 {
			return formatWfpCallError(proc.Name, ret)
		}
		r.mu.Lock()
		r.subHandles[idx] = eventsHandle
		r.netEventTemplates[idx] = tmpl
		r.mu.Unlock()
		return nil
	}

	// Prefer Subscribe2 (NetEvent3), fallback to Subscribe1 (NetEvent2), finally Subscribe0.
	// Even if a proc is present, the call can still fail; try fallbacks before giving up.
	var subscribeErr error
	if err := procFwpmNetEventSubscribe2.Find(); err == nil {
		cb := syscall.NewCallback(wfpNetEventCallback2)
		okAny := false
		if err := subscribeOne(procFwpmNetEventSubscribe2, cb, dropTmpl, netEventSubDrop); err == nil {
			okAny = true
		} else {
			subscribeErr = err
		}
		if err := subscribeOne(procFwpmNetEventSubscribe2, cb, allowTmpl, netEventSubAllow); err == nil {
			okAny = true
		} else if subscribeErr == nil {
			subscribeErr = err
		}
		if okAny {
			r.mu.Lock()
			r.callback2 = cb
			r.subscribeVersion = 2
			r.mu.Unlock()
			return nil
		}
	}

	if err := procFwpmNetEventSubscribe1.Find(); err == nil {
		cb := syscall.NewCallback(wfpNetEventCallback1)
		okAny := false
		if err := subscribeOne(procFwpmNetEventSubscribe1, cb, dropTmpl, netEventSubDrop); err == nil {
			okAny = true
		} else {
			subscribeErr = err
		}
		if err := subscribeOne(procFwpmNetEventSubscribe1, cb, allowTmpl, netEventSubAllow); err == nil {
			okAny = true
		} else if subscribeErr == nil {
			subscribeErr = err
		}
		if okAny {
			r.mu.Lock()
			r.callback1 = cb
			r.subscribeVersion = 1
			r.mu.Unlock()
			return nil
		}
	}

	if err := procFwpmNetEventSubscribe0.Find(); err != nil {
		if subscribeErr != nil {
			return subscribeErr
		}
		return fmt.Errorf("no supported net event subscribe function available: %w", err)
	}
	cb := syscall.NewCallback(wfpNetEventCallback0)
	if err := subscribeOne(procFwpmNetEventSubscribe0, cb, dropTmpl, netEventSubDrop); err != nil {
		if subscribeErr != nil {
			return subscribeErr
		}
		return err
	}
	r.mu.Lock()
	r.callback0 = cb
	r.subscribeVersion = 0
	r.mu.Unlock()
	return nil
}

func (r *WindowsReader) cleanup() error {
	var errOut error
	r.cleanupOnce.Do(func() {
		r.mu.RLock()
		engine := r.engineHandle
		subs := r.subHandles
		r.mu.RUnlock()

		if engine != 0 {
			for _, sub := range subs {
				if sub == 0 {
					continue
				}
				ret, _, _ := procFwpmNetEventUnsubscribe0.Call(engine, sub)
				if ret != 0 && errOut == nil {
					errOut = formatWfpCallError("FwpmNetEventUnsubscribe0", ret)
				}
			}
		}

		if engine != 0 {
			ret, _, _ := procFwpmEngineClose0.Call(engine)
			if ret != 0 && errOut == nil {
				errOut = formatWfpCallError("FwpmEngineClose0", ret)
			}
		}

		r.mu.Lock()
		r.engineHandle = 0
		r.subHandles = [2]uintptr{}
		r.netEventTemplates = [2]*wfpNetEventTemplate{}
		r.eventCh = nil
		r.inCh = nil
		r.deduper = nil
		r.layerCache = nil
		r.callback0 = 0
		r.callback1 = 0
		r.callback2 = 0
		r.subscribeVersion = -1
		r.ztapOnlyEffective = false
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
	w, ok := wfpNetEvent2ToWfpEvent(ev)
	if !ok {
		return
	}
	r.enqueueWfpEvent(w)
}

func (r *WindowsReader) handleNetEvent0(ev *fwpmNetEvent0) {
	if ev == nil {
		return
	}

	r.mu.RLock()
	ztapOnly := r.ztapOnlyEffective
	r.mu.RUnlock()
	if ztapOnly {
		// Older NetEvent0 lacks enough metadata to reliably correlate to ZTAP.
		return
	}
	// Best-effort: FWPM_NET_EVENT0 doesn't include msFwpDirection.
	if ev.Type != fwpmNetEventTypeClassifyDrop {
		return
	}

	drop := (*fwpmNetEventClassifyDrop0)(unsafe.Pointer(ev.Data))
	if drop == nil {
		return
	}

	w := wfpEvent{
		typ:        ev.Type,
		filterID:   drop.FilterId,
		layerID:    drop.LayerId,
		msDir:      0,
		ipVersion:  ev.Header.Prefix.IPVersion,
		proto:      ev.Header.Prefix.IPProto,
		localAddr:  ev.Header.Prefix.LocalAddr,
		remoteAddr: ev.Header.Prefix.RemoteAddr,
		localPort:  ev.Header.Prefix.LocalPort,
		remotePort: ev.Header.Prefix.RemotePort,
	}
	r.enqueueWfpEvent(w)
}

func (r *WindowsReader) handleNetEvent3(ev *fwpmNetEvent3) {
	w, ok := wfpNetEvent3ToWfpEvent(ev)
	if !ok {
		return
	}
	r.enqueueWfpEvent(w)
}

func (r *WindowsReader) enqueueWfpEvent(ev wfpEvent) {
	r.mu.RLock()
	ch := r.inCh
	r.mu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- ev:
	default:
		dropped := r.droppedInCh.Add(1)
		if dropped == 1 || dropped%10000 == 0 {
			logging.Warnf("dropping WFP net events (queue full): dropped=%d", dropped)
		}
	}
}

func wfpNetEvent2ToWfpEvent(ev *fwpmNetEvent2) (wfpEvent, bool) {
	if ev == nil {
		return wfpEvent{}, false
	}
	if ev.Type != fwpmNetEventTypeClassifyAllow && ev.Type != fwpmNetEventTypeClassifyDrop {
		return wfpEvent{}, false
	}

	out := wfpEvent{
		typ:        ev.Type,
		ipVersion:  ev.Header.Prefix.IPVersion,
		proto:      ev.Header.Prefix.IPProto,
		localAddr:  ev.Header.Prefix.LocalAddr,
		remoteAddr: ev.Header.Prefix.RemoteAddr,
		localPort:  ev.Header.Prefix.LocalPort,
		remotePort: ev.Header.Prefix.RemotePort,
	}

	switch ev.Type {
	case fwpmNetEventTypeClassifyAllow:
		allow := (*fwpmNetEventClassifyAllow0)(unsafe.Pointer(ev.Data))
		if allow == nil {
			return wfpEvent{}, false
		}
		out.filterID = allow.FilterId
		out.layerID = allow.LayerId
		out.msDir = allow.MsFwpDirection
	case fwpmNetEventTypeClassifyDrop:
		drop := (*fwpmNetEventClassifyDrop1)(unsafe.Pointer(ev.Data))
		if drop == nil {
			return wfpEvent{}, false
		}
		out.filterID = drop.FilterId
		out.layerID = drop.LayerId
		out.msDir = drop.MsFwpDirection
	}

	return out, true
}

func wfpNetEvent3ToWfpEvent(ev *fwpmNetEvent3) (wfpEvent, bool) {
	if ev == nil {
		return wfpEvent{}, false
	}
	if ev.Type != fwpmNetEventTypeClassifyAllow && ev.Type != fwpmNetEventTypeClassifyDrop {
		return wfpEvent{}, false
	}

	p := ev.Header.Header2.Prefix
	out := wfpEvent{
		typ:        ev.Type,
		ipVersion:  p.IPVersion,
		proto:      p.IPProto,
		localAddr:  p.LocalAddr,
		remoteAddr: p.RemoteAddr,
		localPort:  p.LocalPort,
		remotePort: p.RemotePort,
	}

	switch ev.Type {
	case fwpmNetEventTypeClassifyAllow:
		allow := (*fwpmNetEventClassifyAllow0)(unsafe.Pointer(ev.Data))
		if allow == nil {
			return wfpEvent{}, false
		}
		out.filterID = allow.FilterId
		out.layerID = allow.LayerId
		out.msDir = allow.MsFwpDirection
	case fwpmNetEventTypeClassifyDrop:
		drop := (*fwpmNetEventClassifyDrop1)(unsafe.Pointer(ev.Data))
		if drop == nil {
			return wfpEvent{}, false
		}
		out.filterID = drop.FilterId
		out.layerID = drop.LayerId
		out.msDir = drop.MsFwpDirection
	}

	return out, true
}

func wfpNetEvent2ToRawFlowEvent(ev *fwpmNetEvent2) (RawFlowEvent, bool) {
	w, ok := wfpNetEvent2ToWfpEvent(ev)
	if !ok {
		return RawFlowEvent{}, false
	}
	// Used only in tests; no layer-based direction inference.
	var r WindowsReader
	return r.wfpEventToRawFlowEvent(w)
}

func wfpNetEvent3ToRawFlowEvent(ev *fwpmNetEvent3) (RawFlowEvent, bool) {
	w, ok := wfpNetEvent3ToWfpEvent(ev)
	if !ok {
		return RawFlowEvent{}, false
	}
	// Used only in tests; no layer-based direction inference.
	var r WindowsReader
	return r.wfpEventToRawFlowEvent(w)
}
