//go:build !linux && !windows

package cli

import "testing"

func TestCreateFlowReader_OtherPlatform(t *testing.T) {
	reader := createFlowReader()
	if reader == nil {
		t.Fatalf("expected non-nil flow reader")
	}
	if !reader.Available() {
		t.Fatalf("expected simulated flow reader to be available")
	}
}
