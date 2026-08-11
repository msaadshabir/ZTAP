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

func TestCreateAnomalyFlowReader_OtherPlatform(t *testing.T) {
	reader, err := createAnomalyFlowReader()
	if err == nil {
		t.Fatalf("expected anomaly reader setup to fail on unsupported platform, got %v", reader)
	}
	if reader != nil {
		t.Fatalf("expected no reader on unsupported platform, got %T", reader)
	}
}
