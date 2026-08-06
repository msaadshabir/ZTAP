// Command bpfgen generates the eBPF Go bindings for internal/enforcer without
// committing binary artifacts: it runs bpf2go to compile bpf/filter.c and
// then inlines the resulting object bytes into the generated Go source, so
// the repository contains no *.o files (see Scorecard Binary-Artifacts).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	outputStem = "bpf"
	targets    = "bpfel,bpfeb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bpfgen:", err)
		os.Exit(1)
	}
}

func run() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	pkgDir := filepath.Join(repoRoot, "internal", "enforcer")

	args := []string{
		"run", "github.com/cilium/ebpf/cmd/bpf2go",
		"-no-strip",
		"-target", targets,
		outputStem, "../../bpf/filter.c",
		"--", "-I../../bpf",
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = pkgDir
	cmd.Env = append(hostEnv(), "GOPACKAGE=enforcer")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bpf2go: %w", err)
	}

	for _, variant := range []string{"bpfel", "bpfeb"} {
		objectFile := filepath.Join(pkgDir, outputStem+"_"+variant+".o")
		goFile := filepath.Join(pkgDir, outputStem+"_"+variant+".go")
		if err := inlineObject(goFile, objectFile); err != nil {
			return err
		}
		if err := os.Remove(objectFile); err != nil {
			return fmt.Errorf("remove %s: %w", objectFile, err)
		}
	}
	return nil
}

// inlineObject replaces the go:embed directive in the bpf2go-generated file
// with an inline byte literal so no binary artifact is committed.
func inlineObject(goFile, objectFile string) error {
	data, err := os.ReadFile(objectFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", objectFile, err)
	}
	content, err := os.ReadFile(goFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", goFile, err)
	}

	embedName := filepath.Base(objectFile)
	old := fmt.Sprintf("// Do not access this directly.\n//\n//go:embed %s\nvar _BpfBytes []byte\n", embedName)
	if !strings.Contains(string(content), old) {
		return fmt.Errorf("unexpected generated layout in %s (embed block not found)", goFile)
	}

	const bytesPerLine = 16

	var b strings.Builder
	b.WriteString("// Do not access this directly.\n")
	b.WriteString("//\n")
	b.WriteString("// _BpfBytes holds the eBPF object inlined by tools/bpfgen so the\n")
	b.WriteString("// repository contains no binary artifacts; regenerate with\n")
	b.WriteString("// `go generate ./internal/enforcer/...`.\n")
	b.WriteString("var _BpfBytes = []byte(\n")
	line := ""
	chunk := 0
	for i := 0; i < len(data); i++ {
		line += fmt.Sprintf("\\x%02x", data[i])
		if (i+1)%bytesPerLine == 0 {
			b.WriteString(indentFor(chunk) + "\"" + line + "\" +\n")
			line = ""
			chunk++
		}
	}
	if line != "" {
		b.WriteString(indentFor(chunk) + "\"" + line + "\" +\n")
	}
	b.WriteString("\t\t\"\",\n)\n")

	out := strings.Replace(string(content), old, b.String(), 1)
	return os.WriteFile(goFile, []byte(out), 0o600)
}

// indentFor returns the gofmt-compatible indentation for a string-literal
// chunk: the first line is indented one tab, continuation lines two tabs.
func indentFor(chunk int) string {
	if chunk == 0 {
		return "\t"
	}
	return "\t\t"
}

// hostEnv returns the current environment with GOOS/GOARCH/CGO_ENABLED
// stripped so the spawned bpf2go always builds natively (go generate may be
// invoked with GOOS=linux from a macOS/Windows checkout).
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if key == "GOOS" || key == "GOARCH" || key == "CGO_ENABLED" {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", cwd)
		}
		dir = parent
	}
}
