//go:build windows

package flow

import "syscall"

var (
	modkernel32        = syscall.NewLazyDLL("kernel32.dll")
	procGetTickCount64 = modkernel32.NewProc("GetTickCount64")
)

func getTickCount64() uint64 {
	r1, r2, _ := procGetTickCount64.Call()
	// On 32-bit windows, the 64-bit return is split across r1/r2.
	return uint64(r1) | (uint64(r2) << 32)
}

func init() {
	// GetTickCount64 returns milliseconds since system boot.
	uptimeNsFunc = func() int64 {
		ms := getTickCount64()
		// Clamp to int64; overflow requires centuries of uptime.
		if ms > uint64(^uint64(0)>>1)/1_000_000 {
			return int64(^uint64(0) >> 1)
		}
		return int64(ms) * 1_000_000
	}
}
