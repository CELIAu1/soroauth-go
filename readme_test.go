package soroauth

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readmeSnippet names one fenced ```go block in README.md, in the order it
// appears, and the real source file its content must be extracted from.
//
// Adding a third Go example to the README means adding both a
// "internal/readmesnippets/<name>.go" file with a matching
// "// snippet:start <name>" / "// snippet:end <name>" pair, and an entry
// here — TestReadmeSnippetsMatchTheirSource fails loudly on a count mismatch
// rather than silently skipping an unregistered block.
var readmeSnippets = []struct {
	name       string
	sourceFile string
}{
	{name: "quickstart", sourceFile: "quickstart.go"},
	{name: "delegates", sourceFile: "delegates.go"},
	{name: "allowresign", sourceFile: "allowresign.go"},
}

var goFencePattern = regexp.MustCompile("(?s)```go\n(.*?)```")

// TestReadmeSnippetsMatchTheirSource asserts every fenced ```go block in
// README.md is exactly (modulo tabs-vs-spaces, and the blank line the marker
// comments leave behind) the marked region of its real, compiling source in
// internal/readmesnippets. See CONTRIBUTING.md's "Verifying README snippets
// compile": this test catches the README drifting from its source; a
// snippet that no longer compiles at all is caught separately, by the
// ordinary `go build ./...` CI already runs, since that package carries no
// build tag.
func TestReadmeSnippetsMatchTheirSource(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	matches := goFencePattern.FindAllStringSubmatch(string(readme), -1)
	if len(matches) != len(readmeSnippets) {
		t.Fatalf("README.md has %d fenced ```go blocks, but readmeSnippets (this file) names %d — "+
			"keep the two in sync so every block is checked", len(matches), len(readmeSnippets))
	}

	for i, snip := range readmeSnippets {
		t.Run(snip.name, func(t *testing.T) {
			path := filepath.Join("internal", "readmesnippets", snip.sourceFile)
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}

			marked, err := extractMarkedRegion(string(source), snip.name)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}

			want := normalizeSnippet(marked)
			got := normalizeSnippet(matches[i][1])
			if want != got {
				t.Errorf("README.md's %q fenced ```go block has drifted from the marked region in %s.\n\n"+
					"--- %s (source of truth) ---\n%s\n\n--- README.md ---\n%s",
					snip.name, path, path, want, got)
			}
		})
	}
}

// extractMarkedRegion returns the text strictly between a
// "// snippet:start <name>" and "// snippet:end <name>" comment pair.
func extractMarkedRegion(source, name string) (string, error) {
	startMarker := fmt.Sprintf("// snippet:start %s", name)
	endMarker := fmt.Sprintf("// snippet:end %s", name)

	startIdx := strings.Index(source, startMarker)
	if startIdx == -1 {
		return "", fmt.Errorf("no %q marker found", startMarker)
	}
	body := source[startIdx+len(startMarker):]

	endIdx := strings.Index(body, endMarker)
	if endIdx == -1 {
		return "", fmt.Errorf("no %q marker found", endMarker)
	}
	return body[:endIdx], nil
}

// normalizeSnippet makes a Go source region and a README fenced block
// comparable: it trims the blank lines the marker comments themselves leave
// behind, expands tabs to the four spaces README.md's fences use, and
// dedents by the shallowest indentation among non-blank lines so a snippet
// nested one function deeper in its source file still lines up with how it
// reads at the top level of a fenced block.
func normalizeSnippet(s string) string {
	lines := strings.Split(s, "\n")

	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	for i, line := range lines {
		lines[i] = strings.ReplaceAll(line, "\t", "    ")
	}

	minIndent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if minIndent == -1 || indent < minIndent {
			minIndent = indent
		}
	}
	if minIndent > 0 {
		for i, line := range lines {
			if strings.TrimSpace(line) == "" {
				lines[i] = ""
				continue
			}
			lines[i] = line[minIndent:]
		}
	}

	return strings.Join(lines, "\n")
}
