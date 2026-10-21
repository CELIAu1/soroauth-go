package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workflowDir is the repository's workflow directory, relative to this package.
const workflowDir = "../../.github/workflows"

// TestPathsFilteredWorkflowsIncludeThemselves enforces the rule that a
// workflow with a top-level `paths:` filter must list its own file.
//
// Why this is a test and not a convention: a `paths:`-filtered workflow
// produces no check row at all when it does not match — not a skipped one — so
// a change to a workflow that does not list itself cannot be validated by its
// own run, and nothing about that is visible on the pull request. #294 added a
// job to ci-adapters.yml and merged with that job never having executed once,
// because the filter did not name the file being edited.
//
// Every workflow complies today. This test is what keeps the next one honest.
func TestPathsFilteredWorkflowsIncludeThemselves(t *testing.T) {
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}

	// A scan that matched nothing would pass forever while enforcing nothing.
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		body := string(raw)
		if !regexp.MustCompile(`(?m)^\s+paths:`).MatchString(body) {
			continue
		}
		checked++
		if !strings.Contains(body, "workflows/"+name) {
			t.Errorf("%s has a paths: filter but does not list its own path.\n"+
				"Add `- '.github/workflows/%s'` to every paths: block in it, or an edit "+
				"to this workflow cannot run it and the change lands unvalidated.", name, name)
		}
	}

	if checked == 0 {
		t.Fatal("no paths-filtered workflow was examined; this test would pass vacuously")
	}
	t.Logf("%d paths-filtered workflows checked, all list their own path", checked)
}
