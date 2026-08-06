package logging

import "testing"

func TestFatalUsesExitFn(t *testing.T) {
	old := exitFn
	t.Cleanup(func() { exitFn = old })

	code := 0
	exitFn = func(c int) {
		code = c
	}

	Fatal("boom", nil)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
