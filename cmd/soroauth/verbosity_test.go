package main

import (
	"strings"
	"testing"
)

func TestSplitVerbosityAcrossEverySubcommand(t *testing.T) {
	if len(commandSpecs) == 0 {
		t.Fatal("no subcommands; verbosity coverage would pass vacuously")
	}
	for _, spec := range commandSpecs {
		spec := spec
		t.Run(spec.Name, func(t *testing.T) {
			cleaned, level, err := splitVerbosity(spec.Name, []string{"--entry", "value", "--quiet", "--verbose=false"})
			if err != nil {
				t.Fatalf("splitVerbosity: %v", err)
			}
			if level.quiet != true || level.verbose != false {
				t.Fatalf("level = %+v, want quiet", level)
			}
			want := []string{"--entry", "value", "--verbose=false"}
			if strings.Join(cleaned, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("cleaned = %q, want %q (the value of --entry must not be eaten)", cleaned, want)
			}
		})
	}
}

func TestSplitVerbosityMutualExclusion(t *testing.T) {
	for _, args := range [][]string{
		{"--quiet", "--verbose"},
		{"--quiet=true", "--verbose"},
		{"--quiet", "--verbose=true"},
	} {
		if _, _, err := splitVerbosity("inspect", args); err == nil {
			t.Fatalf("splitVerbosity(%q) accepted both levels", args)
		} else if ExitCode(err) != ExitUsageError {
			t.Fatalf("splitVerbosity(%q) exit = %d, want %d", args, ExitCode(err), ExitUsageError)
		}
	}
}

func TestSplitVerbosityLeavesArgumentsAfterDoubleDash(t *testing.T) {
	cleaned, level, err := splitVerbosity("tui", []string{"--entry", "entry", "--", "--quiet"})
	if err != nil {
		t.Fatalf("splitVerbosity: %v", err)
	}
	if level.quiet {
		t.Fatal("consumed --quiet after --")
	}
	if got := strings.Join(cleaned, " "); got != "--entry entry -- --quiet" {
		t.Fatalf("cleaned = %q", got)
	}
}

func TestQuietPrintsNothingOnSuccess(t *testing.T) {
	vector := loadVector(t, "v2_single_testnet")
	stdout, stderr, err := runCLI(t,
		"inspect",
		"--entry", vector.UnsignedEntryXDR,
		"--json",
		"--quiet",
	)
	if err != nil {
		t.Fatalf("inspect --quiet failed: %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want nothing", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want nothing", stderr)
	}
}

func TestQuietStillReportsFailure(t *testing.T) {
	stdout, stderr, err := runCLI(t, "inspect", "--entry", "not-base64", "--quiet")
	if err == nil {
		t.Fatal("invalid input succeeded")
	}
	if ExitCode(err) != ExitUsageError {
		t.Fatalf("exit = %d, want %d", ExitCode(err), ExitUsageError)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want nothing", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want nothing; main prints the returned error", stderr)
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Fatalf("error = %q, want the input error", err)
	}
}

func TestVerboseExplainsTheVerdictWithoutEchoingTheEntry(t *testing.T) {
	vector := loadVector(t, "v2_single_testnet")
	stdout, stderr, err := runCLI(t,
		"inspect",
		"--entry", vector.UnsignedEntryXDR,
		"--json",
		"--verbose",
	)
	if err != nil {
		t.Fatalf("inspect --verbose failed: %v", err)
	}
	if !strings.Contains(stdout, `"credential_type"`) {
		t.Fatalf("stdout does not contain the result: %q", stdout)
	}
	if !strings.Contains(stderr, "soroauth: inspect: ok") {
		t.Fatalf("stderr = %q, want the verbose verdict", stderr)
	}
	if !strings.Contains(stderr, "credential_type=address_v2") || !strings.Contains(stderr, "delegates=0") {
		t.Fatalf("stderr = %q, want the credential arm and delegate count", stderr)
	}
	if strings.Contains(stderr, vector.UnsignedEntryXDR) {
		t.Fatal("verbose output echoed the entry")
	}
}

func TestVerifyVerboseNamesEachNode(t *testing.T) {
	vector := loadVector(t, "v2_single_testnet")
	stdout, stderr, err := runCLI(t,
		"verify",
		"--entry", vector.SignedEntryXDR,
		"--network", "testnet",
		"--verbose",
	)
	if err != nil {
		t.Fatalf("verify --verbose failed: %v", err)
	}
	if stdout == "" {
		t.Fatal("verify printed no report")
	}
	if !strings.Contains(stderr, ": node ") || !strings.Contains(stderr, "verified") {
		t.Fatalf("stderr = %q, want the per-node verdict", stderr)
	}
}

func TestVerboseNamesTheExitCodeOnFailure(t *testing.T) {
	_, stderr, err := runCLI(t, "inspect", "--entry", "not-base64", "--verbose")
	if err == nil {
		t.Fatal("invalid input succeeded")
	}
	if !strings.Contains(stderr, "soroauth: inspect: exit 2") {
		t.Fatalf("stderr = %q, want the verbose failure verdict", stderr)
	}
}
