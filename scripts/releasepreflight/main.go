package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	apiPageSize = 100
	maxBodySize = 10 << 20
)

var (
	semverTagPattern      = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
	leadingVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+`)
	versionPattern        = `v[0-9]+\.[0-9]+\.[0-9]+`
)

const imageTagPrefix = "ghcr.io/soroauth/soroauth-go:"

type workflowRun struct {
	ID         int64     `json:"id"`
	WorkflowID int64     `json:"workflow_id"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	HeadSHA    string    `json:"head_sha"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type workflowRunPage struct {
	WorkflowRuns []workflowRun `json:"workflow_runs"`
}

func main() {
	version := flag.String("version", os.Getenv("GITHUB_REF_NAME"), "release tag")
	sha := flag.String("sha", os.Getenv("GITHUB_SHA"), "tagged commit SHA")
	repository := flag.String("repository", os.Getenv("GITHUB_REPOSITORY"), "owner/repository")
	flag.Parse()

	if *version == "" || *sha == "" || *repository == "" {
		fail(errors.New("release tag, commit SHA, and repository are required"))
	}
	if err := validateReleaseMetadata(".", *version); err != nil {
		fail(err)
	}

	currentRunID, err := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	if err != nil {
		fail(fmt.Errorf("parse current workflow run ID: %w", err))
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		fail(errors.New("GH_TOKEN is required to inspect workflow runs"))
	}

	client := &http.Client{Timeout: 20 * time.Second}
	runs, err := fetchWorkflowRuns(context.Background(), client, "https://api.github.com", *repository, *sha, token)
	if err != nil {
		fail(err)
	}
	if err := validateWorkflowRuns(runs, *sha, currentRunID); err != nil {
		fail(err)
	}
	fmt.Printf("release preflight passed for %s at %s\n", *version, *sha)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "release preflight:", err)
	os.Exit(1)
}

func validateReleaseMetadata(root, tag string) error {
	if !semverTagPattern.MatchString(tag) {
		return fmt.Errorf("tag %q is not a stable vMAJOR.MINOR.PATCH release", tag)
	}
	version := strings.TrimPrefix(tag, "v")

	changelog, err := readFile(root, "CHANGELOG.md")
	if err != nil {
		return err
	}
	foundChangelogEntry := false
	changelogHeader := regexp.MustCompile(`^## \[` + regexp.QuoteMeta(version) + `\](?:\s|$)`)
	for _, line := range strings.Split(changelog, "\n") {
		if changelogHeader.MatchString(line) {
			foundChangelogEntry = true
			break
		}
	}
	if !foundChangelogEntry {
		return fmt.Errorf("CHANGELOG.md has no entry for %s", version)
	}

	versionedFiles := []struct {
		path    string
		pattern string
	}{
		{"README.md", `(?m)^## Status\s*\n\s*\*\*(` + versionPattern + `)\. Unaudited\.\*\*`},
		{"SECURITY.md", `(?m)^## Status of this library\s*\n\s*\n\*\*(` + versionPattern + `), unaudited\.\*\*`},
		{"docs/passkeys.md", `The library itself is (` + versionPattern + `) and \*\*unaudited\*\*\.`},
		{"docs/signers.md", `The library as a whole is (` + versionPattern + `) and \*\*unaudited\*\*\.`},
		{"doc.go", `(?m)^// Status: (` + versionPattern + `), unaudited\.$`},
		{"CITATION.cff", `(?m)^version: ([0-9]+\.[0-9]+\.[0-9]+)$`},
		{"server/openapi.yaml", `(?m)^\s+example: (` + versionPattern + `)$`},
	}
	for _, item := range versionedFiles {
		content, err := readFile(root, item.path)
		if err != nil {
			return err
		}
		match := regexp.MustCompile(item.pattern).FindStringSubmatch(content)
		if len(match) != 2 {
			return fmt.Errorf("%s is missing its machine-checked current release status", item.path)
		}
		expected := tag
		if item.path == "CITATION.cff" {
			expected = version
		}
		if match[1] != expected {
			return fmt.Errorf("%s reports %s; release tag is %s", item.path, match[1], tag)
		}
	}

	readme, err := readFile(root, "README.md")
	if err != nil {
		return err
	}
	imageTags := findImageTags(readme)
	if len(imageTags) == 0 {
		return errors.New("README.md has no versioned GHCR image reference")
	}
	for _, foundTag := range imageTags {
		if foundTag != tag {
			return fmt.Errorf("README.md refers to stale image tag %s; release tag is %s", foundTag, tag)
		}
	}

	for _, path := range []string{"wasm/ts/package.json", "wasm/ts/package-lock.json"} {
		content, err := readFile(root, path)
		if err != nil {
			return err
		}
		var manifest struct {
			Version  string `json:"version"`
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal([]byte(content), &manifest); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if manifest.Version != version {
			return fmt.Errorf("%s declares version %q; release tag requires %q", path, manifest.Version, version)
		}
		if path == "wasm/ts/package-lock.json" {
			rootPackage, ok := manifest.Packages[""]
			if !ok || rootPackage.Version != version {
				return fmt.Errorf("%s root package declares version %q; release tag requires %q", path, rootPackage.Version, version)
			}
		}
	}

	examplePackage, err := readFile(root, "examples/wallet-freighter/package.json")
	if err != nil {
		return err
	}
	var exampleManifest struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(examplePackage), &exampleManifest); err != nil {
		return fmt.Errorf("parse examples/wallet-freighter/package.json: %w", err)
	}
	if exampleManifest.Dependencies["@soroauth/wasm"] != version {
		return fmt.Errorf("examples/wallet-freighter/package.json depends on @soroauth/wasm %q; release tag requires %q",
			exampleManifest.Dependencies["@soroauth/wasm"], version)
	}
	return nil
}

func findImageTags(content string) []string {
	parts := strings.Split(content, imageTagPrefix)
	if len(parts) < 2 {
		return nil
	}
	var tags []string
	for _, part := range parts[1:] {
		if tag := leadingVersionPattern.FindString(part); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func readFile(root, path string) (string, error) {
	content, err := os.ReadFile(root + "/" + path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(content), nil
}

func fetchWorkflowRuns(ctx context.Context, client *http.Client, apiBase, repository, sha, token string) ([]workflowRun, error) {
	if strings.Contains(repository, "/") == false || strings.Contains(repository, "..") {
		return nil, fmt.Errorf("invalid repository %q", repository)
	}
	base, err := url.Parse(apiBase)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub API URL: %w", err)
	}
	var runs []workflowRun
	for page := 1; ; page++ {
		endpoint := *base
		endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/repos/" + repository + "/actions/runs"
		query := endpoint.Query()
		query.Set("head_sha", sha)
		query.Set("per_page", strconv.Itoa(apiPageSize))
		query.Set("page", strconv.Itoa(page))
		endpoint.RawQuery = query.Encode()

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("create workflow-runs request: %w", err)
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("query workflow runs for %s: %w", sha, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxBodySize))
		response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read workflow-runs response: %w", readErr)
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("query workflow runs for %s: GitHub returned %s: %s", sha, response.Status, strings.TrimSpace(string(body)))
		}
		var result workflowRunPage
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decode workflow-runs response: %w", err)
		}
		runs = append(runs, result.WorkflowRuns...)
		if len(result.WorkflowRuns) < apiPageSize {
			return runs, nil
		}
	}
}

func validateWorkflowRuns(runs []workflowRun, sha string, currentRunID int64) error {
	latest := make(map[string]workflowRun)
	for _, run := range runs {
		if run.HeadSHA != sha || run.ID == currentRunID {
			continue
		}
		key := strconv.FormatInt(run.WorkflowID, 10)
		if run.WorkflowID == 0 {
			key = run.Path
		}
		prior, exists := latest[key]
		if !exists || run.UpdatedAt.After(prior.UpdatedAt) || (run.UpdatedAt.Equal(prior.UpdatedAt) && run.ID > prior.ID) {
			latest[key] = run
		}
	}
	if len(latest) == 0 {
		return fmt.Errorf("GitHub reports no workflow runs for commit %s (excluding this release run)", sha)
	}

	keys := make([]string, 0, len(latest))
	for key := range latest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		run := latest[key]
		name := run.Name
		if name == "" {
			name = run.Path
		}
		if run.Status != "completed" {
			return fmt.Errorf("workflow %q on %s is %s, not completed", name, sha, run.Status)
		}
		if run.Conclusion != "success" {
			return fmt.Errorf("workflow %q on %s concluded %q, not success", name, sha, run.Conclusion)
		}
	}
	return nil
}
