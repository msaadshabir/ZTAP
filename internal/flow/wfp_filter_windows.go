//go:build windows

package flow

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFwpmFilterGetById0 = modfwpuclnt.NewProc("FwpmFilterGetById0")
	procFwpmFreeMemory0    = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

// Minimal WFP structs required for FilterId -> Provider/Sublayer correlation.
// Layout matches fwpmtypes.h (FWPM_FILTER0) on 64-bit Windows.
//
// We intentionally only model the fields we need, but we keep the struct shape
// identical up through SubLayerKey to ensure correct offsets.
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpByteBlob0 struct {
	size uint32
	data *byte
}

type fwpmFilter0 struct {
	filterKey    windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob0
	layerKey     windows.GUID
	subLayerKey  windows.GUID
}

type filterOwnerCache struct {
	mu    sync.Mutex
	m     map[uint64]bool
	limit int
}

func newFilterOwnerCache(limit int) *filterOwnerCache {
	return &filterOwnerCache{m: make(map[uint64]bool, limit), limit: limit}
}

func (c *filterOwnerCache) get(id uint64) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	return v, ok
}

func (c *filterOwnerCache) set(id uint64, v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limit > 0 && len(c.m) >= c.limit {
		// Simple bounded behavior: clear cache when it grows too large.
		// FilterIds are typically stable while ZTAP runs, so this is acceptable.
		c.m = make(map[uint64]bool, c.limit)
	}
	c.m[id] = v
}

func isWindowsGUIDEqual(a windows.GUID, b windows.GUID) bool {
	return a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3 && a.Data4 == b.Data4
}

func (r *WindowsReader) isZTAPFilter(filterID uint64) (bool, error) {
	if filterID == 0 {
		return false, nil
	}

	if r.filterCache != nil {
		if v, ok := r.filterCache.get(filterID); ok {
			return v, nil
		}
	}

	r.mu.RLock()
	engine := r.engineHandle
	r.mu.RUnlock()
	if engine == 0 {
		return false, errors.New("WFP engine is not open")
	}

	var f *fwpmFilter0
	ret, _, _ := procFwpmFilterGetById0.Call(
		engine,
		uintptr(filterID),
		uintptr(unsafe.Pointer(&f)),
	)
	if ret != 0 {
		return false, fmt.Errorf("FwpmFilterGetById0 failed with error 0x%x", ret)
	}
	if f == nil {
		return false, nil
	}

	isZTAP := false
	if f.providerKey != nil && isWindowsGUIDEqual(*f.providerKey, ztapWFPProviderGUID) {
		isZTAP = true
	}
	if !isZTAP && isWindowsGUIDEqual(f.subLayerKey, ztapWFPSublayerGUID) {
		isZTAP = true
	}

	// Free memory allocated by WFP for the returned filter.
	// FwpmFreeMemory0 expects a pointer-to-pointer.
	procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&f)))

	if r.filterCache != nil {
		r.filterCache.set(filterID, isZTAP)
	}
	return isZTAP, nil
}
