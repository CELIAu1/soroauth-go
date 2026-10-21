package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateReleaseMetadata(t *testing.T) {
	t.Run("complete release metadata", func(t *testing.T) {
		root := releaseFixture(t, "v1.2.3")
		if err := validateReleaseMetadata(root, "v1.2.3"); err != nil {
			t.Fatalf("validateReleaseMetadata() error = %v", err)
		}
	})

	for _, test := range []struct {
		name        string
		path        string
		replacement string
		want        string
	}{
		{
			name:        "missing changelog entry",
			path:        "CHANGELOG.md",
			replacement: "# Changelog\n",
			want:        "CHANGELOG.md has no entry",
		},
		{
			name:        "stale readme status",
			path:        "README.md",
			replacement: "## Status\n\n**v1.2.2. Unaudited.**\n",
			want:        "README.md reports v1.2.2",
		},
		{
			name:        "stale security status",
			path:        "SECURITY.md",
			replacement: "## Status of this library\n\n**v1.2.2, unaudited.**\n",
			want:        "SECURITY.md reports v1.2.2",
		},
		{
			name:        "stale passkey guide status",
			path:        "docs/passkeys.md",
			replacement: "The library itself is v1.2.2 and **unaudited**.\n",
			want:        "docs/passkeys.md reports v1.2.2",
		},
		{
			name:        "stale signer guide status",
			path:        "docs/signers.md",
			replacement: "The library as a whole is v1.2.2 and **unaudited**.\n",
			want:        "docs/signers.md reports v1.2.2",
		},
		{
			name:        "stale versioned image reference",
			path:        "README.md",
			replacement: "## Status\n\n**v1.2.3. Unaudited.**\ndocker pull ghcr.io/soroauth/soroauth-go:v1.2.2\n",
			want:        "stale image tag v1.2.2",
		},
		{
			name:        "stale npm package version",
			path:        "wasm/ts/package.json",
			replacement: `{"name":"@soroauth/wasm","version":"1.2.2"}`,
			want:        `declares version "1.2.2"`,
		},
		{
			name:        "stale citation version",
			path:        "CITATION.cff",
			replacement: "version: 1.2.2\n",
			want:        "CITATION.cff reports 1.2.2",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := releaseFixture(t, "v1.2.3")
			writeFixtureFile(t, root, test.path, test.replacement)
			err := validateReleaseMetadata(root, "v1.2.3")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateReleaseMetadata() error = %v, want substring %q", err, test.want)
			}
		})
	}

	t.Run("rejects non stable tags", func(t *testing.T) {
		err := validateReleaseMetadata(t.TempDir(), "v1.2.3-rc.1")
		if err == nil || !strings.Contains(err.Error(), "not a stable") {
			t.Fatalf("validateReleaseMetadata() error = %v, want unstable-tag error", err)
		}
	})
}

func TestValidateWorkflowRuns(t *testing.T) {
	const sha = "abc123"
	for _, test := range []struct {
		name    string
		runs    []workflowRun
		wantErr string
	}{
		{
			name: "all latest workflow runs passed",
			runs: []workflowRun{
				{ID: 1, WorkflowID: 10, Name: "CI", HeadSHA: sha, Status: "completed", Conclusion: "success"},
				{ID: 2, WorkflowID: 11, Name: "Spellcheck", HeadSHA: sha, Status: "completed", Conclusion: "success"},
			},
		},
		{
			name: "later successful rerun supersedes failure",
			runs: []workflowRun{
				{ID: 1, WorkflowID: 10, Name: "CI", HeadSHA: sha, Status: "completed", Conclusion: "failure"},
				{ID: 2, WorkflowID: 10, Name: "CI", HeadSHA: sha, Status: "completed", Conclusion: "success"},
			},
		},
		{
			name: "red workflow refuses release",
			runs: []workflowRun{
				{ID: 1, WorkflowID: 10, Name: "CI", HeadSHA: sha, Status: "completed", Conclusion: "success"},
				{ID: 2, WorkflowID: 11, Name: "Spellcheck", HeadSHA: sha, Status: "completed", Conclusion: "failure"},
			},
			wantErr: `workflow "Spellcheck"`,
		},
		{
			name: "incomplete workflow refuses release",
			runs: []workflowRun{
				{ID: 1, WorkflowID: 10, Name: "CI", HeadSHA: sha, Status: "in_progress"},
			},
			wantErr: `workflow "CI"`,
		},
		{
			name: "no matching run refuses release",
			runs: []workflowRun{
				{ID: 1, WorkflowID: 10, Name: "CI", HeadSHA: "different", Status: "completed", Conclusion: "success"},
			},
			wantErr: "no workflow runs",
		},
		{
			name: "only current release run refuses release",
			runs: []workflowRun{
				{ID: 99, WorkflowID: 10, Name: "release", HeadSHA: sha, Status: "in_progress"},
			},
			wantErr: "no workflow runs",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateWorkflowRuns(test.runs, sha, 99)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateWorkflowRuns() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateWorkflowRuns() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestFetchWorkflowRuns(t *testing.T) {
	t.Run("filters by exact commit and authenticates", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/repos/soroauth/soroauth-go/actions/runs" {
				t.Errorf("request path = %q", r.URL.Path)
			}
			if r.URL.Query().Get("head_sha") != "abc123" || r.URL.Query().Get("page") != "1" {
				t.Errorf("request query = %v", r.URL.Query())
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(workflowRunPage{
				WorkflowRuns: []workflowRun{{ID: 1, WorkflowID: 3, HeadSHA: "abc123"}},
			})
		}))
		defer server.Close()

		runs, err := fetchWorkflowRuns(context.Background(), server.Client(), server.URL, "soroauth/soroauth-go", "abc123", "test-token")
		if err != nil {
			t.Fatalf("fetchWorkflowRuns() error = %v", err)
		}
		if len(runs) != 1 || runs[0].HeadSHA != "abc123" {
			t.Fatalf("fetchWorkflowRuns() = %+v, want one run on requested SHA", runs)
		}
	})

	t.Run("reads every page", func(t *testing.T) {
		requestedPages := make([]string, 0, 2)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			requestedPages = append(requestedPages, page)
			runs := make([]workflowRun, 0, apiPageSize)
			if page == "1" {
				for i := 0; i < apiPageSize; i++ {
					runs = append(runs, workflowRun{ID: int64(i + 1), HeadSHA: "abc123"})
				}
			} else {
				runs = append(runs, workflowRun{ID: 101, HeadSHA: "abc123"})
			}
			if err := json.NewEncoder(w).Encode(workflowRunPage{WorkflowRuns: runs}); err != nil {
				t.Errorf("encode workflow-runs page: %v", err)
			}
		}))
		defer server.Close()

		runs, err := fetchWorkflowRuns(context.Background(), server.Client(), server.URL, "soroauth/soroauth-go", "abc123", "test-token")
		if err != nil {
			t.Fatalf("fetchWorkflowRuns() error = %v", err)
		}
		if len(runs) != 101 || strings.Join(requestedPages, ",") != "1,2" {
			t.Fatalf("fetched %d runs on pages %v, want 101 runs on pages 1 and 2", len(runs), requestedPages)
		}
	})

	t.Run("GitHub API failures are errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		defer server.Close()
		_, err := fetchWorkflowRuns(context.Background(), server.Client(), server.URL, "soroauth/soroauth-go", "abc123", "test-token")
		if err == nil || !strings.Contains(err.Error(), "403 Forbidden") {
			t.Fatalf("fetchWorkflowRuns() error = %v, want GitHub API failure", err)
		}
	})
}

func releaseFixture(t *testing.T, tag string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"CHANGELOG.md":                           "# Changelog\n\n## [" + strings.TrimPrefix(tag, "v") + "] - 2026-10-12\n",
		"README.md":                              "## Status\n\n**" + tag + ". Unaudited.**\n\ndocker pull ghcr.io/soroauth/soroauth-go:" + tag + "\n",
		"SECURITY.md":                            "## Status of this library\n\n**" + tag + ", unaudited.**\n",
		"docs/passkeys.md":                       "The library itself is " + tag + " and **unaudited**.\n",
		"docs/signers.md":                        "The library as a whole is " + tag + " and **unaudited**.\n",
		"doc.go":                                 "// Status: " + tag + ", unaudited.\n",
		"CITATION.cff":                           "version: " + strings.TrimPrefix(tag, "v") + "\n",
		"server/openapi.yaml":                    "        example: " + tag + "\n",
		"wasm/ts/package.json":                   `{"name":"@soroauth/wasm","version":"` + strings.TrimPrefix(tag, "v") + `"}`,
		"wasm/ts/package-lock.json":              `{"version":"` + strings.TrimPrefix(tag, "v") + `","packages":{"":{"version":"` + strings.TrimPrefix(tag, "v") + `"}}}`,
		"examples/wallet-freighter/package.json": `{"dependencies":{"@soroauth/wasm":"` + strings.TrimPrefix(tag, "v") + `"}}`,
	}
	for path, content := range files {
		writeFixtureFile(t, root, path, content)
	}
	return root
}

func writeFixtureFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
}

func Example_validateWorkflowRuns() {
	err := validateWorkflowRuns([]workflowRun{
		{ID: 7, WorkflowID: 9, Name: "Spellcheck", HeadSHA: "deadbeef", Status: "completed", Conclusion: "failure"},
	}, "deadbeef", 0)
	fmt.Println(err != nil)
	// Output: true
}
