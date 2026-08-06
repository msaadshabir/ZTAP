//go:build windows

package cli

import "testing"

func TestCreateFlowReader_Windows(t *testing.T) {
	reader := createFlowReader()
	if reader == nil {
		t.Fatalf("expected non-nil flow reader")
	}
	if !reader.Available() {
		t.Fatalf("expected windows flow reader to be available")
	}
}
