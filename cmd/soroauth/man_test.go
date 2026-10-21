package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runManCLI drives runMan directly and captures both streams, the way the other
// subcommand tests drive their run functions.
func runManCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut strings.Builder
	err = runMan(args, &out, &errOut)
	return out.String(), errOut.String(), err
}

// TestManPageCoversEveryCommandAndFlag is the acceptance criterion the man page
// exists to meet: every subcommand and every flag appears in it. The lists come
// from commandSpecs, so this also proves the generator did not skip a table
// entry — and commandSpecs itself is pinned to the real flag sets by
// TestSpecsMatchTheRealFlagSets, which is what makes the claim transitive.
func TestManPageCoversEveryCommandAndFlag(t *testing.T) {
	page, stderr, err := runManCLI(t)
	if err != nil {
		t.Fatalf("man failed: %v (stderr: %s)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("man wrote to stderr: %q", stderr)
	}
	if !strings.HasPrefix(page, ".TH SOROAUTH 1 ") {
		t.Fatalf("page does not start with a .TH heading:\n%.120s", page)
	}
	if !strings.Contains(page, ".SH NAME") || !strings.Contains(page, ".SH SYNOPSIS") {
		t.Error("page is missing its NAME or SYNOPSIS section")
	}

	for _, cmd := range commandSpecs {
		if !strings.Contains(page, ".B "+cmd.Name+"\n") {
			t.Errorf("page does not document subcommand %q", cmd.Name)
		}
		for _, f := range cmd.Flags {
			if !strings.Contains(page, `\-\-`+f.Name) {
				t.Errorf("page does not document %s's flag --%s", cmd.Name, f.Name)
			}
		}
	}

	// The global flags the dispatcher handles without a subcommand.
	for _, want := range []string{`\-\-version`, `\-h, \-\-help`} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not document the global flag %q", want)
		}
	}
}

// TestManPageIsDeterministic pins the property the page's doc comment claims:
// no build timestamp, so two calls emit identical bytes. A page that changed
// on every build would show up as a diff in every packaging repo that vendors
// it.
func TestManPageIsDeterministic(t *testing.T) {
	first, _, err := runManCLI(t)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, _, err := runManCLI(t)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Error("man produced different output across calls")
	}
}

// TestManJSONMode asserts --json wraps the exact page the plain mode prints, so
// a packager can fetch it either way and get the same bytes.
func TestManJSONMode(t *testing.T) {
	plain, _, err := runManCLI(t)
	if err != nil {
		t.Fatalf("plain mode: %v", err)
	}
	out, _, err := runManCLI(t, "--json")
	if err != nil {
		t.Fatalf("json mode: %v", err)
	}
	var decoded manOutput
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decoding --json output: %v\noutput: %s", err, out)
	}
	if decoded.Format != "man" {
		t.Errorf("format field = %q, want %q", decoded.Format, "man")
	}
	if decoded.Page != plain {
		t.Error("--json page differs from the plain-mode output")
	}
}

// TestManOutWritesTheFile proves the packaging path: --out writes the page and
// leaves stdout empty, so a build step that redirects stdout cannot end up with
// the page in two places.
func TestManOutWritesTheFile(t *testing.T) {
	plain, _, err := runManCLI(t)
	if err != nil {
		t.Fatalf("plain mode: %v", err)
	}

	path := filepath.Join(t.TempDir(), "soroauth.1")
	stdout, stderr, err := runManCLI(t, "--out", path)
	if err != nil {
		t.Fatalf("--out failed: %v (stderr: %s)", err, stderr)
	}
	if stdout != "" {
		t.Errorf("--out wrote to stdout as well: %q", stdout)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if string(written) != plain {
		t.Error("the file written by --out differs from the page on stdout")
	}
}

// TestManUsageErrors asserts the failure contract: --json with --out is refused
// rather than resolved by precedence, and an unwritable path is a general error
// that names the path and still reports non-zero.
func TestManUsageErrors(t *testing.T) {
	t.Run("json and out together", func(t *testing.T) {
		stdout, _, err := runManCLI(t, "--json", "--out", filepath.Join(t.TempDir(), "soroauth.1"))
		if got := ExitCode(err); got != ExitUsageError {
			t.Errorf("exit code = %d, want %d", got, ExitUsageError)
		}
		var got jsonErrorOutput
		if decodeErr := json.Unmarshal([]byte(stdout), &got); decodeErr != nil {
			t.Fatalf("stdout is not a structured JSON error: %v\n%s", decodeErr, stdout)
		}
		if got.Code != "usage_error" || got.Field != "--out" || got.ExitCode != ExitUsageError {
			t.Errorf("unexpected JSON refusal: %+v", got)
		}
	})

	t.Run("unwritable path", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("making %s read-only: %v", dir, err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		stdout, _, err := runManCLI(t, "--out", filepath.Join(dir, "soroauth.1"))
		if err == nil {
			t.Fatalf("writing into a read-only directory succeeded, printing %q", stdout)
		}
		if !strings.Contains(err.Error(), "soroauth.1") {
			t.Errorf("error %q does not name the path it could not write", err)
		}
	})
}

// TestManPageParsesWithRealRoff renders the page with whichever troff-family
// formatter is installed. A man page that is only ever read as text by its own
// test is not evidence that a packager's man will show anything; this at least
// proves a real formatter accepts it. Both tools are optional here — a
// contributor without either still runs every other check — so the test skips
// rather than fails when neither is present.
func TestManPageParsesWithRealRoff(t *testing.T) {
	page, _, err := runManCLI(t)
	if err != nil {
		t.Fatalf("man failed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "soroauth.1")
	if err := os.WriteFile(path, []byte(page), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	for _, formatter := range []struct {
		name string
		args []string
	}{
		{name: "mandoc", args: []string{"-Tascii", path}},
		{name: "groff", args: []string{"-man", "-Tascii", path}},
	} {
		binary, err := exec.LookPath(formatter.name)
		if err != nil {
			continue
		}
		out, err := exec.Command(binary, formatter.args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s rejected the man page: %v\noutput:\n%s", formatter.name, err, out)
		}
		rendered := stripOverstrike(string(out))
		if !strings.Contains(rendered, "SOROAUTH") {
			t.Errorf("%s rendered a page with no SOROAUTH heading:\n%s", formatter.name, rendered)
		}
		if !strings.Contains(rendered, "--entry") {
			t.Errorf("%s rendered a page in which a flag's dashes are broken:\n%s", formatter.name, rendered)
		}
		return
	}
	t.Skip("neither mandoc nor groff is on PATH")
}

// stripOverstrike removes the backspace overstrike a terminal formatter emits
// for bold and underline: bold "N" is rendered "N\bN", and underlined "c" is
// rendered "_\bc".
//
// Without this the assertions below match against those sequences rather than
// the text, so "--entry" is never found and "NAME" reads as "NNAAMMEE". That
// is environment-specific: mandoc on macOS overstrikes where the groff builds
// on the CI runners do not, so the test passed in CI and failed for anyone
// working on a Mac. This is `col -b` in eight lines, so the test does not gain
// a dependency on col being installed.
func stripOverstrike(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\b' {
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// TestManThroughTheDispatcher asserts the subcommand is reachable the way a
// user reaches it, through run().
func TestManThroughTheDispatcher(t *testing.T) {
	stdout, stderr, err := runCLI(t, "man")
	if err != nil {
		t.Fatalf("dispatcher rejected man: %v (stderr: %s)", err, stderr)
	}
	if !strings.HasPrefix(stdout, ".TH SOROAUTH 1 ") {
		t.Errorf("dispatcher output is not the man page:\n%.120s", stdout)
	}
}
