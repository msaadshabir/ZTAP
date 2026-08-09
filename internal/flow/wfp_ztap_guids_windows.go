//go:build windows

package flow

import "golang.org/x/sys/windows"

// ZTAP WFP GUIDs.
//
// NOTE: These values must remain in sync with the GUIDs used by the Windows
// enforcer (`internal/enforcer/wfp_types.go`). They are duplicated here to avoid
// introducing a dependency from `internal/flow` to `internal/enforcer`.
var (
	ztapWFPProviderGUID = windows.GUID{
		Data1: 0x7F8E9D0C,
		Data2: 0x1B2A,
		Data3: 0x4D3E,
		Data4: [8]byte{0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A},
	}

	ztapWFPSublayerGUID = windows.GUID{
		Data1: 0xA1B2C3D4,
		Data2: 0xE5F6,
		Data3: 0x4A5B,
		Data4: [8]byte{0x8C, 0x9D, 0x0E, 0x1F, 0x2A, 0x3B, 0x4C, 0x5D},
	}
)
