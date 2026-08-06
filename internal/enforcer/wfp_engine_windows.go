//go:build windows

package enforcer

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	FWPM_SESSION_FLAG_DYNAMIC uint32 = 0x00000001

	// FWP_DATA_TYPE values (fwptypes.h)
	FWP_UINT8        uint32 = 1
	FWP_UINT16       uint32 = 2
	FWP_UINT32       uint32 = 3
	FWP_UINT64       uint32 = 4
	FWP_V4_ADDR_MASK uint32 = 19
	FWP_V6_ADDR_MASK uint32 = 20
)

var (
	modfwpuclnt = syscall.NewLazyDLL("fwpuclnt.dll")

	procFwpmEngineOpen0              = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0             = modfwpuclnt.NewProc("FwpmEngineClose0")
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
	procFwpmFreeMemory0              = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

// WFP Structs (simplified for Go)

type fwpmSession0 struct {
	sessionGuid          windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	sid                  uintptr
	username             *uint16
	kernelMode           bool
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmProvider0 struct {
	providerGuid windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	serviceName  *uint16
	binaryName   *uint16
	serviceId    uintptr
}

type fwpmSublayer0 struct {
	subLayerGuid windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerGuid *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmFilter0 struct {
	filterGuid          windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerGuid        *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	context             uint64
	reserved            uintptr
	filterId            uint64
	effectiveWeight     fwpValue0
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpConditionValue0
}

type fwpConditionValue0 struct {
	type_ uint32
	value [16]byte // Union of various types
}

type fwpmAction0 struct {
	type_      uint32
	calloutKey windows.GUID
}

type fwpValue0 struct {
	type_ uint32
	value [16]byte // Union
}

type fwpV4AddrMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrMask struct {
	addr         [16]byte
	prefixLength uint8
	_            [3]byte
}

// realWFPEngine is the production implementation using fwpuclnt.dll.
type realWFPEngine struct {
	handle uintptr
}

func (e *realWFPEngine) Open() error {
	var session fwpmSession0
	session.flags = FWPM_SESSION_FLAG_DYNAMIC

	r1, _, _ := procFwpmEngineOpen0.Call(
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&session)),
		uintptr(unsafe.Pointer(&e.handle)),
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) Close() error {
	if e.handle == 0 {
		return nil
	}
	r1, _, _ := procFwpmEngineClose0.Call(e.handle)
	if r1 != 0 {
		return fmt.Errorf("FwpmEngineClose0 failed with error 0x%x", r1)
	}
	e.handle = 0
	return nil
}

func (e *realWFPEngine) BeginTransaction() error {
	r1, _, _ := procFwpmTransactionBegin0.Call(e.handle, 0)
	if r1 != 0 {
		return fmt.Errorf("FwpmTransactionBegin0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) CommitTransaction() error {
	r1, _, _ := procFwpmTransactionCommit0.Call(e.handle)
	if r1 != 0 {
		return fmt.Errorf("FwpmTransactionCommit0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) AbortTransaction() error {
	r1, _, _ := procFwpmTransactionAbort0.Call(e.handle)
	if r1 != 0 {
		return fmt.Errorf("FwpmTransactionAbort0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) AddProvider(name, description string, guid *GUID) error {
	var provider fwpmProvider0
	provider.providerGuid = guid.toWindowsGUID()
	provider.displayData.name = windows.StringToUTF16Ptr(name)
	provider.displayData.description = windows.StringToUTF16Ptr(description)

	r1, _, _ := procFwpmProviderAdd0.Call(
		e.handle,
		uintptr(unsafe.Pointer(&provider)),
		0,
	)
	// FWP_E_ALREADY_EXISTS is 0x80320009
	if r1 != 0 && r1 != 0x80320009 {
		return fmt.Errorf("FwpmProviderAdd0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) AddSublayer(name, description string, guid *GUID, providerGuid *GUID, weight uint16) error {
	var sublayer fwpmSublayer0
	sublayer.subLayerGuid = guid.toWindowsGUID()
	sublayer.displayData.name = windows.StringToUTF16Ptr(name)
	sublayer.displayData.description = windows.StringToUTF16Ptr(description)
	if providerGuid != nil {
		pg := providerGuid.toWindowsGUID()
		sublayer.providerGuid = &pg
	}
	sublayer.weight = weight

	r1, _, _ := procFwpmSubLayerAdd0.Call(
		e.handle,
		uintptr(unsafe.Pointer(&sublayer)),
		0,
	)
	if r1 != 0 && r1 != 0x80320009 {
		return fmt.Errorf("FwpmSubLayerAdd0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) AddFilter(filter *WFPSpec) error {
	var f fwpmFilter0
	f.displayData.name = windows.StringToUTF16Ptr(filter.Name)
	f.displayData.description = windows.StringToUTF16Ptr(filter.Description)
	f.layerKey = filter.LayerKey.toWindowsGUID()
	f.subLayerKey = filter.SublayerKey.toWindowsGUID()
	if filter.ProviderKey != nil {
		pk := filter.ProviderKey.toWindowsGUID()
		f.providerGuid = &pk
	}

	// Weight
	f.weight.type_ = FWP_UINT64
	*(*uint64)(unsafe.Pointer(&f.weight.value[0])) = filter.Weight

	// Action
	f.action.type_ = filter.ActionType

	// Conditions
	if len(filter.Conditions) > 0 {
		conditions := make([]fwpmFilterCondition0, len(filter.Conditions))
		v4MaskCount := 0
		v6MaskCount := 0
		for _, c := range filter.Conditions {
			if _, ok := c.Value.(V4AddrMask); ok {
				v4MaskCount++
			}
			if _, ok := c.Value.(V6AddrMask); ok {
				v6MaskCount++
			}
		}
		v4Masks := make([]fwpV4AddrMask, v4MaskCount)
		v6Masks := make([]fwpV6AddrMask, v6MaskCount)
		v4MaskIdx := 0
		v6MaskIdx := 0

		for i, c := range filter.Conditions {
			conditions[i].fieldKey = c.FieldKey.toWindowsGUID()
			conditions[i].matchType = c.MatchType

			// Map value to fwpConditionValue0
			switch v := c.Value.(type) {
			case V4AddrMask:
				conditions[i].conditionValue.type_ = FWP_V4_ADDR_MASK
				v4Masks[v4MaskIdx] = fwpV4AddrMask{addr: v.Addr, mask: v.Mask}
				ptr := uintptr(unsafe.Pointer(&v4Masks[v4MaskIdx]))
				*(*uintptr)(unsafe.Pointer(&conditions[i].conditionValue.value[0])) = ptr
				v4MaskIdx++
			case V6AddrMask:
				conditions[i].conditionValue.type_ = FWP_V6_ADDR_MASK
				v6Masks[v6MaskIdx] = fwpV6AddrMask{addr: v.Addr, prefixLength: v.PrefixLength}
				ptr := uintptr(unsafe.Pointer(&v6Masks[v6MaskIdx]))
				*(*uintptr)(unsafe.Pointer(&conditions[i].conditionValue.value[0])) = ptr
				v6MaskIdx++
			case uint32:
				conditions[i].conditionValue.type_ = FWP_UINT32
				*(*uint32)(unsafe.Pointer(&conditions[i].conditionValue.value[0])) = v
			case uint16:
				conditions[i].conditionValue.type_ = FWP_UINT16
				*(*uint16)(unsafe.Pointer(&conditions[i].conditionValue.value[0])) = v
			case uint8:
				conditions[i].conditionValue.type_ = FWP_UINT8
				*(*uint8)(unsafe.Pointer(&conditions[i].conditionValue.value[0])) = v
			default:
				return fmt.Errorf("unsupported WFP condition value type %T", c.Value)
			}
		}
		f.numFilterConditions = uint32(len(conditions))
		f.filterCondition = &conditions[0]
	}

	r1, _, _ := procFwpmFilterAdd0.Call(
		e.handle,
		uintptr(unsafe.Pointer(&f)),
		0,
		0,
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) DeleteFilterByKey(key *GUID) error {
	gk := key.toWindowsGUID()
	r1, _, _ := procFwpmFilterDeleteByKey0.Call(
		e.handle,
		uintptr(unsafe.Pointer(&gk)),
	)
	if r1 != 0 && r1 != 0x80320004 { // FWP_E_FILTER_NOT_FOUND
		return fmt.Errorf("FwpmFilterDeleteByKey0 failed with error 0x%x", r1)
	}
	return nil
}

func (e *realWFPEngine) DeleteFiltersByProvider(providerGuid *GUID) error {
	var enumHandle uintptr
	r1, _, _ := procFwpmFilterCreateEnumHandle0.Call(
		e.handle,
		0,
		uintptr(unsafe.Pointer(&enumHandle)),
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterCreateEnumHandle0 failed with error 0x%x", r1)
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(e.handle, enumHandle)

	pg := providerGuid.toWindowsGUID()

	for {
		var entries **fwpmFilter0
		var numEntries uint32
		r1, _, _ := procFwpmFilterEnum0.Call(
			e.handle,
			enumHandle,
			100,
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&numEntries)),
		)
		if r1 != 0 {
			return fmt.Errorf("FwpmFilterEnum0 failed with error 0x%x", r1)
		}
		if numEntries == 0 {
			break
		}

		// Convert entries to a slice
		filterPtrs := (*[1 << 20]*fwpmFilter0)(unsafe.Pointer(entries))[:numEntries:numEntries]

		for _, f := range filterPtrs {
			if f.providerGuid != nil && *f.providerGuid == pg {
				// Delete by key
				procFwpmFilterDeleteByKey0.Call(
					e.handle,
					uintptr(unsafe.Pointer(&f.filterGuid)),
				)
			}
		}

		// Free memory allocated by FwpmFilterEnum0.
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
	}
	return nil
}

// toWindowsGUID converts our local GUID to windows.GUID.
func (g GUID) toWindowsGUID() windows.GUID {
	return windows.GUID{
		Data1: g.Data1,
		Data2: g.Data2,
		Data3: g.Data3,
		Data4: g.Data4,
	}
}
