package main

import (
	"bufio"
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
		coverProfile = flag.String("coverprofile", "", "path to coverprofile output")
		repoRoot     = flag.String("repo", "", "repo root directory")
		maxFiles     = flag.Int("max-files", 25, "max uncovered files to print")
		maxBlocks    = flag.Int("max-blocks", 5, "max uncovered blocks per file")
		dneLines     = flag.Int("do-not-edit-lines", 40, "number of initial lines to scan for DO NOT EDIT")
	)
	flag.Parse()

	if strings.TrimSpace(*coverProfile) == "" || strings.TrimSpace(*repoRoot) == "" {
		fatalf("usage: %s -coverprofile <path> -repo <repo-root>", filepath.Base(os.Args[0]))
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
	failing := 0

	repoSlash := filepath.ToSlash(repoAbs)

	for rawFile, blocks := range fc {
		rel := normalizeCoverPath(rawFile, repoSlash, modPath)
		if !strings.HasPrefix(rel, "pkg/") {
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
		if total != covered {
			failing++
		}
		_ = total
		_ = covered
		_ = uncovered
	}

	// Second pass: build a consistent report map for included failing files.
	report := make(map[string]*fileCov)
	for rawFile, blocks := range fc {
		rel := normalizeCoverPath(rawFile, repoSlash, modPath)
		if !strings.HasPrefix(rel, "pkg/") {
			continue
		}
		if isExcludedByPattern(rel) {
			continue
		}
		if hasDoNotEdit(repoAbs, rel, *dneLines) {
			continue
		}

		total, covered, uncovered := summarizeBlocks(blocks)
		if total == covered {
			continue
		}
		report[rel] = &fileCov{file: rel, totalStmts: total, coverStmts: covered, uncovered: uncovered}
	}

	if len(report) == 0 {
		fmt.Printf("coverage gate: ok (%d pkg files checked)\n", checked)
		return
	}

	files := make([]*fileCov, 0, len(report))
	for _, v := range report {
		files = append(files, v)
	}
	sort.Slice(files, func(i, j int) bool {
		iUnc := files[i].totalStmts - files[i].coverStmts
		jUnc := files[j].totalStmts - files[j].coverStmts
		if iUnc != jUnc {
			return iUnc > jUnc
		}
		return files[i].file < files[j].file
	})

	uncFiles := len(files)
	uncStmts := 0
	for _, f := range files {
		uncStmts += (f.totalStmts - f.coverStmts)
	}

	fmt.Printf("coverage gate: FAIL (%d uncovered statements across %d/%d pkg files)\n", uncStmts, uncFiles, checked)
	limitFiles := *maxFiles
	if limitFiles <= 0 || limitFiles > len(files) {
		limitFiles = len(files)
	}
	for i := 0; i < limitFiles; i++ {
		f := files[i]
		unc := f.totalStmts - f.coverStmts
		fmt.Printf("- %s: %d/%d uncovered statements\n", f.file, unc, f.totalStmts)
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
	if len(files) > limitFiles {
		fmt.Printf("... (%d more uncovered files)\n", len(files)-limitFiles)
	}

	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
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
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
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
		if strings.HasPrefix(p, modPrefix) {
			return path.Clean(strings.TrimPrefix(p, modPrefix))
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
