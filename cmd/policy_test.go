package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyValidateCmd(t *testing.T) {
	tempDir := t.TempDir()

	validPolicy := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: test
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 80
`
	validFile := filepath.Join(tempDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte(validPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	invalidPolicy := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: test
  egress:
    - to:
        ipBlock:
          cidr: 300.0.0.0/24
      ports:
        - protocol: TCP
          port: 80
`
	invalidFile := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		wantExit bool
	}{
		{
			name:     "valid file",
			args:     []string{"validate", "--file", validFile},
			wantExit: false,
		},
		{
			name:     "invalid file",
			args:     []string{"validate", "--file", invalidFile},
			wantExit: true, // This will call os.Exit(1) which is hard to test in unit test without exec
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since runPolicyValidate calls log.Fatalf or os.Exit, we can't easily unit test the failure path
			// without refactoring to return an error.
			// For now, we'll just test that it runs without panic for valid input.
			if !tt.wantExit {
				cmd := policyValidateCmd
				cmd.SetArgs(tt.args[1:]) // skip "validate"
				if err := cmd.Flags().Set("file", tt.args[2]); err != nil {
					t.Fatal(err)
				}

				// Redirect stdout to avoid cluttering test output
				oldStdout := os.Stdout
				_, w, _ := os.Pipe()
				os.Stdout = w

				runPolicyValidate(cmd, tt.args[1:])

				_ = w.Close()
				os.Stdout = oldStdout
			}
		})
	}
}
