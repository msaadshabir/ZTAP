//go:build windows

package flow

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procFwpmLayerGetById0 = modfwpuclnt.NewProc("FwpmLayerGetById0")

// Common ALE layer keys used for direction inference when MsFwpDirection is
// missing or invalid.
var (
	fwpmLayerAleAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1,
		Data2: 0x05a7,
		Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	fwpmLayerAleAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b,
		Data2: 0x319f,
		Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	fwpmLayerAleAuthRecvAcceptV4 = windows.GUID{
		Data1: 0xe1cd9fe7,
		Data2: 0xf4b5,
		Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
	}
	fwpmLayerAleAuthRecvAcceptV6 = windows.GUID{
		Data1: 0xa3b42c97,
		Data2: 0x9f04,
		Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
	}
)

func inferDirectionFromLayerKey(layerKey windows.GUID) (uint8, bool) {
	switch {
	case isWindowsGUIDEqual(layerKey, fwpmLayerAleAuthConnectV4):
		return DirectionEgress, true
	case isWindowsGUIDEqual(layerKey, fwpmLayerAleAuthConnectV6):
		return DirectionEgress, true
	case isWindowsGUIDEqual(layerKey, fwpmLayerAleAuthRecvAcceptV4):
		return DirectionIngress, true
	case isWindowsGUIDEqual(layerKey, fwpmLayerAleAuthRecvAcceptV6):
		return DirectionIngress, true
	default:
		return 0, false
	}
}

type fwpmLayer0 struct {
	LayerKey           windows.GUID
	DisplayData        fwpmDisplayData0
	Flags              uint32
	NumFields          uint32
	Field              uintptr
	DefaultSubLayerKey windows.GUID
	LayerId            uint16
}

type layerKeyCache struct {
	mu sync.Mutex
	m  map[uint16]windows.GUID
}

func newLayerKeyCache() *layerKeyCache {
	return &layerKeyCache{m: make(map[uint16]windows.GUID)}
}

func (c *layerKeyCache) get(id uint16) (windows.GUID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	return v, ok
}

func (c *layerKeyCache) set(id uint16, v windows.GUID) {
	c.mu.Lock()
	c.m[id] = v
	c.mu.Unlock()
}

// layerKeyByID resolves a layer GUID from a numeric layer id.
//
// This is optional (primarily for debugging and future system-wide capture).
func (r *WindowsReader) layerKeyByID(layerID uint16) (windows.GUID, bool, error) {
	if layerID == 0 {
		return windows.GUID{}, false, nil
	}
	if r.layerCache == nil {
		return windows.GUID{}, false, nil
	}
	if v, ok := r.layerCache.get(layerID); ok {
		return v, true, nil
	}

	r.mu.RLock()
	engine := r.engineHandle
	r.mu.RUnlock()
	if engine == 0 {
		return windows.GUID{}, false, errors.New("WFP engine is not open")
	}

	var layer *fwpmLayer0
	ret, _, _ := procFwpmLayerGetById0.Call(
		engine,
		uintptr(layerID),
		uintptr(unsafe.Pointer(&layer)),
	)
	if ret != 0 {
		return windows.GUID{}, false, fmt.Errorf("FwpmLayerGetById0 failed with error 0x%x", ret)
	}
	if layer == nil {
		return windows.GUID{}, false, nil
	}

	key := layer.LayerKey
	procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&layer)))
	r.layerCache.set(layerID, key)
	return key, true, nil
}
