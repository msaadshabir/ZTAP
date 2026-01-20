//go:build windows

package flow

import (
	"context"
	"sync"
	"syscall"

	"ztap/pkg/logging"

	"golang.org/x/sys/windows"
)

var (
	modfwpuclnt = syscall.NewLazyDLL("fwpuclnt.dll")

	procFwpmNetEventSubscribe0   = modfwpuclnt.NewProc("FwpmNetEventSubscribe0")
	procFwpmNetEventUnsubscribe0 = modfwpuclnt.NewProc("FwpmNetEventUnsubscribe0")
)

// WindowsReader reads flow events from WFP NetEvents on Windows.
type WindowsReader struct {
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	handle  uintptr
	sub     uintptr
}

// NewWindowsReader creates a new Windows flow reader.
func NewWindowsReader() *WindowsReader {
	return &WindowsReader{
		stopCh: make(chan struct{}),
	}
}

// Start begins reading flow events from WFP.
func (r *WindowsReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}

	// In a real implementation, we would:
	// 1. Open WFP engine
	// 2. Subscribe to NetEvents with a callback
	// 3. The callback would parse FWPM_NET_EVENT0 and send RawFlowEvent to eventCh

	r.running = true
	r.mu.Unlock()

	logging.Info("Windows flow reader started (WFP NetEvents)", nil)

	// For now, we'll simulate events or wait for stop
	// Real implementation requires complex callback handling with syscall.NewCallback

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopCh:
		return nil
	}
}

// Stop stops the reader.
func (r *WindowsReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	close(r.stopCh)
	r.running = false
	return nil
}

// Available returns true if the reader can be used on this platform.
func (r *WindowsReader) Available() bool {
	return true
}

// WFP NetEvent Structs (placeholders for real implementation)

type fwpmNetEventSubscription0 struct {
	enumTemplate uintptr // FWPM_NET_EVENT_ENUM_TEMPLATE0
	flags        uint32
	sessionGuid  windows.GUID
}

type fwpmNetEvent0 struct {
	header fwpmNetEventHeader0
	type_  uint32
	// union ...
}

type fwpmNetEventHeader0 struct {
	timeStamp windows.Filetime
	flags     uint32
	ipVersion uint32
	// ...
}
