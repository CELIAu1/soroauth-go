// Cross-compile command builds soroauth for multiple targets.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// crossCompileTarget defines a GOOS/GOARCH pair to build for.
type crossCompileTarget struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Binary string `json:"binary"`
}

// crossCompileResult holds the outcome of a single target build.
type crossCompileResult struct {
	Target crossCompileTarget `json:"target"`
	Error  string             `json:"error,omitempty"`
	Size   int64              `json:"size,omitempty"`
	SHA256 string             `json:"sha256,omitempty"`
}

// runCrossCompile builds soroauth for all configured targets.
func runCrossCompile(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("cross-compile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonFlag := flags.Bool("json", false, "emit results as JSON (one object per line)")
	targetsFlag := flags.String("targets", "", "comma-separated GOOS/GOARCH pairs (default: all)")
	outputDir := flags.String("output-dir", "", "directory to write binaries (default: stdout only)")

	if err := flags.Parse(args); err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "parsing flags: %w", err))
	}

	targets, err := parseTargets(*targetsFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "%v", err))
	}

	var results []crossCompileResult

	for _, t := range targets {
		result := crossCompileResult{Target: t}

		binaryName := "soroauth"
		if t.GOOS == "windows" {
			binaryName = "soroauth.exe"
		}
		result.Target.Binary = binaryName

		var outBuf bytes.Buffer
		var errBuf bytes.Buffer

		// Find module root (directory containing go.mod)
		moduleRoot, err := findModuleRoot()
		if err != nil {
			result.Error = fmt.Sprintf("finding module root: %v", err)
			results = append(results, result)
			continue
		}

		// Build from the module root
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", binaryName, "./cmd/soroauth")
		cmd.Dir = moduleRoot
		cmd.Env = append(os.Environ(),
			"GOOS="+t.GOOS,
			"GOARCH="+t.GOARCH,
			"CGO_ENABLED=0",
		)
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		if err := cmd.Run(); err != nil {
			result.Error = strings.TrimSpace(errBuf.String())
			if result.Error == "" {
				result.Error = err.Error()
			}
			results = append(results, result)
			continue
		}

		// Binary is created in the module root
		binaryPath := filepath.Join(moduleRoot, binaryName)
		info, err := os.Stat(binaryPath)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			_ = os.Remove(binaryPath)
			continue
		}
		result.Size = info.Size()

		sha256, err := hashFile(binaryPath)
		if err != nil {
			result.Error = fmt.Sprintf("hashing binary: %v", err)
			_ = os.Remove(binaryPath)
			results = append(results, result)
			continue
		}
		result.SHA256 = sha256

		if *outputDir != "" {
			dest := filepath.Join(*outputDir, binaryName)
			if err := os.Rename(binaryPath, dest); err != nil {
				result.Error = fmt.Sprintf("moving binary: %v", err)
				_ = os.Remove(binaryPath)
				results = append(results, result)
				continue
			}
		} else {
			_ = os.Remove(binaryPath)
		}

		results = append(results, result)
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				return writeJSONError(stdout, true, fmt.Errorf("encoding JSON: %w", err))
			}
		}
		return nil
	}

	// Human-readable output
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(stderr, "FAIL %s/%s: %s\n", r.Target.GOOS, r.Target.GOARCH, r.Error)
		} else {
			fmt.Fprintf(stdout, "OK   %s/%s  %d bytes  sha256:%s\n", r.Target.GOOS, r.Target.GOARCH, r.Size, r.SHA256)
		}
	}

	// Check if any failed
	for _, r := range results {
		if r.Error != "" {
			return newErrorf(ExitGeneralError, "some targets failed")
		}
	}

	return nil
}

func parseTargets(s string) ([]crossCompileTarget, error) {
	// Default targets matching the CI matrix
	defaults := []crossCompileTarget{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "darwin", GOARCH: "amd64"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "amd64"},
	}

	if s == "" {
		return defaults, nil
	}

	var targets []crossCompileTarget
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts := strings.Split(part, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid target format %q, expected GOOS/GOARCH", part)
		}
		goos := parts[0]
		goarch := parts[1]
		if !isValidGOOS(goos) || !isValidGOARCH(goarch) {
			return nil, fmt.Errorf("invalid target %q: unknown GOOS/GOARCH", part)
		}
		targets = append(targets, crossCompileTarget{GOOS: goos, GOARCH: goarch})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets specified")
	}
	return targets, nil
}

func isValidGOOS(s string) bool {
	valid := map[string]bool{
		"linux":   true,
		"darwin":  true,
		"windows": true,
		"freebsd": true,
		"openbsd": true,
		"netbsd":  true,
	}
	return valid[s]
}

func isValidGOARCH(s string) bool {
	valid := map[string]bool{
		"amd64":   true,
		"arm64":   true,
		"386":     true,
		"arm":     true,
		"ppc64":   true,
		"ppc64le": true,
		"s390x":   true,
		"riscv64": true,
	}
	return valid[s]
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found in any parent directory")
}
