package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type block struct {
	startLine int
	startCol  int
	endLine   int
	endCol    int
	stmts     int
	count     int
}

type fileCov struct {
	file       string
	totalStmts int
	coverStmts int
	uncovered  []block
}

func main() {
	var (
		coverProfile   = flag.String("coverprofile", "", "path to coverprofile output")
		repoRoot       = flag.String("repo", "", "repo root directory")
		baselinePath   = flag.String("baseline", "", "path to baseline JSON; when set, fail only on files that drop below their baseline coverage")
		updateBaseline = flag.Bool("update-baseline", false, "write current per-file coverage to -baseline and exit")
		maxFiles       = flag.Int("max-files", 25, "max uncovered files to print")
		maxBlocks      = flag.Int("max-blocks", 5, "max uncovered blocks per file")
		dneLines       = flag.Int("do-not-edit-lines", 40, "number of initial lines to scan for DO NOT EDIT")
	)
	flag.Parse()

	if strings.TrimSpace(*coverProfile) == "" || strings.TrimSpace(*repoRoot) == "" {
		fatalf("usage: %s -coverprofile <path> -repo <repo-root>", filepath.Base(os.Args[0]))
	}
	if *updateBaseline && strings.TrimSpace(*baselinePath) == "" {
		fatalf("-update-baseline requires -baseline")
	}

	repoAbs, err := filepath.Abs(*repoRoot)
	if err != nil {
		fatalf("failed to resolve repo root: %v", err)
	}
	modPath, _ := readModulePath(filepath.Join(repoAbs, "go.mod"))

	fc, err := parseCoverProfile(*coverProfile)
	if err != nil {
		fatalf("failed to read coverprofile: %v", err)
	}

	checked := 0
	summaries := make(map[string]*fileCov)

	repoSlash := filepath.ToSlash(repoAbs)

	for rawFile, blocks := range fc {
		rel := normalizeCoverPath(rawFile, repoSlash, modPath)
		if !isGatedPath(rel) {
			continue
		}
		if isExcludedByPattern(rel) {
			continue
		}
		if hasDoNotEdit(repoAbs, rel, *dneLines) {
			continue
		}

		checked++
		total, covered, uncovered := summarizeBlocks(blocks)
		summaries[rel] = &fileCov{file: rel, totalStmts: total, coverStmts: covered, uncovered: uncovered}
	}

	if *updateBaseline {
		if err := writeBaseline(*baselinePath, summaries); err != nil {
			fatalf("failed to write baseline: %v", err)
		}
		fmt.Printf("coverage baseline: wrote %d files to %s\n", len(summaries), *baselinePath)
		return
	}

	var base baselineFile
	if strings.TrimSpace(*baselinePath) != "" && !*updateBaseline {
		b, err := readBaseline(*baselinePath)
		if err != nil {
			fatalf("failed to read baseline: %v", err)
		}
		base = b
	}

	newFiles := 0
	var failing []*fileCov
	if strings.TrimSpace(*baselinePath) != "" {
		for rel, f := range summaries {
			if f.totalStmts == 0 {
				continue
			}
			min, ok := base.Files[rel]
			if !ok {
				newFiles++
				continue
			}
			if cur := coverageFraction(f); cur < min-1e-9 {
				failing = append(failing, f)
			}
		}
	} else {
		for _, f := range summaries {
			if f.totalStmts != f.coverStmts {
				failing = append(failing, f)
			}
		}
	}

	if len(failing) == 0 {
		if strings.TrimSpace(*baselinePath) != "" {
			fmt.Printf("coverage gate: ok (%d files checked against baseline, %d new files untracked)\n", checked, newFiles)
		} else {
			fmt.Printf("coverage gate: ok (%d pkg files checked)\n", checked)
		}
		return
	}

	sort.Slice(failing, func(i, j int) bool {
		iUnc := failing[i].totalStmts - failing[i].coverStmts
		jUnc := failing[j].totalStmts - failing[j].coverStmts
		if iUnc != jUnc {
			return iUnc > jUnc
		}
		return failing[i].file < failing[j].file
	})

	uncFiles := len(failing)
	uncStmts := 0
	for _, f := range failing {
		uncStmts += (f.totalStmts - f.coverStmts)
	}

	if strings.TrimSpace(*baselinePath) != "" {
		fmt.Printf("coverage gate: FAIL (%d files dropped below their baseline coverage)\n", uncFiles)
	} else {
		fmt.Printf("coverage gate: FAIL (%d uncovered statements across %d/%d pkg files)\n", uncStmts, uncFiles, checked)
	}
	limitFiles := *maxFiles
	if limitFiles <= 0 || limitFiles > len(failing) {
		limitFiles = len(failing)
	}
	for i := 0; i < limitFiles; i++ {
		f := failing[i]
		unc := f.totalStmts - f.coverStmts
		if strings.TrimSpace(*baselinePath) != "" {
			fmt.Printf("- %s: %.2f%% covered (%.2f%% required)\n", f.file, coverageFraction(f)*100, base.Files[f.file]*100)
		} else {
			fmt.Printf("- %s: %d/%d uncovered statements\n", f.file, unc, f.totalStmts)
		}
		limitBlocks := *maxBlocks
		if limitBlocks <= 0 || limitBlocks > len(f.uncovered) {
			limitBlocks = len(f.uncovered)
		}
		for bi := 0; bi < limitBlocks; bi++ {
			b := f.uncovered[bi]
			fmt.Printf("  %d.%d,%d.%d (%d)\n", b.startLine, b.startCol, b.endLine, b.endCol, b.stmts)
		}
		if len(f.uncovered) > limitBlocks {
			fmt.Printf("  ... (%d more uncovered blocks)\n", len(f.uncovered)-limitBlocks)
		}
	}
	if len(failing) > limitFiles {
		fmt.Printf("... (%d more failing files)\n", len(failing)-limitFiles)
	}

	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

// baselineFile records the minimum accepted per-file statement coverage
// (covered/total as a fraction in [0,1]). The gate fails only when a file's
// coverage drops below its recorded entry.
type baselineFile struct {
	Version int                `json:"version"`
	Files   map[string]float64 `json:"files"`
}

func coverageFraction(f *fileCov) float64 {
	if f.totalStmts == 0 {
		return 1
	}
	return float64(f.coverStmts) / float64(f.totalStmts)
}

func readBaseline(p string) (baselineFile, error) {
	var b baselineFile
	data, err := os.ReadFile(p)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	if b.Files == nil {
		b.Files = map[string]float64{}
	}
	return b, nil
}

func writeBaseline(p string, summaries map[string]*fileCov) error {
	b := baselineFile{Version: 1, Files: make(map[string]float64, len(summaries))}
	for rel, f := range summaries {
		if f.totalStmts == 0 {
			continue
		}
		b.Files[rel] = coverageFraction(f)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(p, data, 0o600)
}

// isGatedPath reports whether a repo-relative path is coverage-gated.
func isGatedPath(rel string) bool {
	return strings.HasPrefix(rel, "pkg/") || strings.HasPrefix(rel, "cmd/")
}

func readModulePath(goModPath string) (string, error) {
	f, err := os.Open(goModPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if after, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(after), nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", errors.New("module path not found")
}

func parseCoverProfile(p string) (map[string][]block, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	res := make(map[string][]block)
	s := bufio.NewScanner(f)
	// coverprofile lines can be long when paths are long
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	first := true
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(line, "mode: ") {
				continue
			}
		}

		bf, b, ok := parseCoverLine(line)
		if !ok {
			return nil, fmt.Errorf("invalid coverprofile line: %q", line)
		}
		res[bf] = append(res[bf], b)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

var winAbsRe = regexp.MustCompile(`^[A-Za-z]:/`)

func normalizeCoverPath(rawFile, repoSlash, modulePath string) string {
	p := strings.ReplaceAll(rawFile, "\\", "/")

	// If absolute, prefer making it relative to the repo root.
	if strings.HasPrefix(p, "/") || winAbsRe.MatchString(p) {
		repo := strings.TrimSuffix(repoSlash, "/")
		if repo != "" {
			repoPrefix := repo + "/"
			lowerP := strings.ToLower(p)
			lowerRepoPrefix := strings.ToLower(repoPrefix)
			if strings.HasPrefix(lowerP, lowerRepoPrefix) {
				return path.Clean(p[len(repoPrefix):])
			}
		}
		return path.Clean(p)
	}

	if modulePath != "" {
		modPrefix := strings.TrimSuffix(modulePath, "/") + "/"
		if after, ok := strings.CutPrefix(p, modPrefix); ok {
			return path.Clean(after)
		}
	}

	return path.Clean(p)
}

func isExcludedByPattern(rel string) bool {
	// Explicitly exclude bpf2go generated enforcement stubs.
	if strings.HasPrefix(rel, "pkg/enforcer/bpf_bpf") && strings.HasSuffix(rel, ".go") {
		return true
	}
	return false
}

func hasDoNotEdit(repoAbs, rel string, maxLines int) bool {
	if maxLines <= 0 {
		return false
	}
	abspath := filepath.Join(repoAbs, filepath.FromSlash(rel))
	f, err := os.Open(abspath)
	if err != nil {
		// If we cannot read the file, don't silently exclude it.
		return false
	}
	defer func() { _ = f.Close() }()

	return scanFirstLinesFor(f, maxLines, "DO NOT EDIT")
}

func scanFirstLinesFor(r io.Reader, maxLines int, needle string) bool {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for i := 0; i < maxLines && s.Scan(); i++ {
		if strings.Contains(s.Text(), needle) {
			return true
		}
	}
	return false
}

func summarizeBlocks(blocks []block) (total int, covered int, uncovered []block) {
	blocks = mergeDuplicateBlocks(blocks)
	for _, b := range blocks {
		total += b.stmts
		if b.count > 0 {
			covered += b.stmts
		} else {
			uncovered = append(uncovered, b)
		}
	}
	// Make output deterministic.
	sort.Slice(uncovered, func(i, j int) bool {
		if uncovered[i].startLine != uncovered[j].startLine {
			return uncovered[i].startLine < uncovered[j].startLine
		}
		if uncovered[i].startCol != uncovered[j].startCol {
			return uncovered[i].startCol < uncovered[j].startCol
		}
		if uncovered[i].endLine != uncovered[j].endLine {
			return uncovered[i].endLine < uncovered[j].endLine
		}
		return uncovered[i].endCol < uncovered[j].endCol
	})
	return total, covered, uncovered
}

func mergeDuplicateBlocks(blocks []block) []block {
	if len(blocks) <= 1 {
		return blocks
	}

	type key struct {
		sl int
		sc int
		el int
		ec int
		s  int
	}
	merged := make(map[key]block, len(blocks))
	for _, b := range blocks {
		k := key{sl: b.startLine, sc: b.startCol, el: b.endLine, ec: b.endCol, s: b.stmts}
		if existing, ok := merged[k]; ok {
			existing.count += b.count
			merged[k] = existing
			continue
		}
		merged[k] = b
	}

	res := make([]block, 0, len(merged))
	for _, b := range merged {
		res = append(res, b)
	}
	// Deterministic order for later processing.
	sort.Slice(res, func(i, j int) bool {
		if res[i].startLine != res[j].startLine {
			return res[i].startLine < res[j].startLine
		}
		if res[i].startCol != res[j].startCol {
			return res[i].startCol < res[j].startCol
		}
		if res[i].endLine != res[j].endLine {
			return res[i].endLine < res[j].endLine
		}
		if res[i].endCol != res[j].endCol {
			return res[i].endCol < res[j].endCol
		}
		return res[i].stmts < res[j].stmts
	})
	return res
}

func parseCoverLine(line string) (file string, b block, ok bool) {
	// <file>:<startLine>.<startCol>,<endLine>.<endCol> <numStmts> <count>
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return "", block{}, false
	}
	fileAndRange := parts[0]
	stmtsStr := parts[1]
	countStr := parts[2]

	stmts, err := strconv.Atoi(stmtsStr)
	if err != nil {
		return "", block{}, false
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return "", block{}, false
	}

	idx := strings.LastIndex(fileAndRange, ":")
	if idx <= 0 {
		return "", block{}, false
	}
	file = fileAndRange[:idx]
	rangePart := fileAndRange[idx+1:]

	comma := strings.Index(rangePart, ",")
	if comma <= 0 {
		return "", block{}, false
	}
	start := rangePart[:comma]
	end := rangePart[comma+1:]

	sl, sc, ok1 := parsePos(start)
	el, ec, ok2 := parsePos(end)
	if !ok1 || !ok2 {
		return "", block{}, false
	}

	return file, block{startLine: sl, startCol: sc, endLine: el, endCol: ec, stmts: stmts, count: count}, true
}

func parsePos(s string) (line int, col int, ok bool) {
	dot := strings.Index(s, ".")
	if dot <= 0 {
		return 0, 0, false
	}
	lineStr := s[:dot]
	colStr := s[dot+1:]
	l, err := strconv.Atoi(lineStr)
	if err != nil {
		return 0, 0, false
	}
	c, err := strconv.Atoi(colStr)
	if err != nil {
		return 0, 0, false
	}
	return l, c, true
}
