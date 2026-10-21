package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// runBatchCLI drives the dispatcher through runWithStdin and keeps both
// streams, because batch mode's text contract splits results (stdout) from
// failures (stderr) and the older stdin helper drops stderr.
func runBatchCLI(t *testing.T, env map[string]string, stdinContent string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = runWithStdin(args, &out, &errOut, func(key string) string { return env[key] }, strings.NewReader(stdinContent))
	return out.String(), errOut.String(), err
}

// batchFile writes one batch file in the test's temporary directory: the lines
// are joined and newline-terminated, so the trailing newline a real file has is
// part of what the tests exercise. No lines writes an empty file.
func batchFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "entries.b64")
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// batchElement is one element of a batch JSON report.
type batchElement struct {
	Entry         int             `json:"entry"`
	Result        json.RawMessage `json:"result"`
	Error         string          `json:"error"`
	SchemaVersion int             `json:"schema_version"`
	Code          string          `json:"code"`
	Message       string          `json:"message"`
	Field         string          `json:"field"`
	ExitCode      int             `json:"exit_code"`
}

func decodeBatchReport(t *testing.T, stdout string) []batchElement {
	t.Helper()
	var got []batchElement
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("the batch report is not one JSON array: %v\n%s", err, stdout)
	}
	return got
}

func TestInspectBatchReportsEveryInput(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	// A blank line between inputs must not consume an index: the malformed
	// line is entry 2, the second good one is entry 3.
	file := batchFile(t, v.UnsignedEntryXDR, "", "!not-base64!", v.UnsignedEntryXDR)

	stdout, stderr, err := runBatchCLI(t, nil, "", "inspect", "--entries", file)
	if err == nil {
		t.Fatal("a batch with a malformed line succeeded")
	}
	if code := ExitCode(err); code != ExitUsageError {
		t.Errorf("exit code = %d, want %d (the malformed line's)", code, ExitUsageError)
	}
	if !strings.Contains(err.Error(), "1 of 3 entries failed") {
		t.Errorf("summary = %q, want it to count 1 of 3", err)
	}
	if !strings.Contains(stdout, "entry 1:") || !strings.Contains(stdout, "entry 3:") {
		t.Errorf("stdout does not label both good inputs with their positions:\n%s", stdout)
	}
	if strings.Contains(stdout, "entry 2:") {
		t.Errorf("a failed input produced a stdout report:\n%s", stdout)
	}
	if !strings.Contains(stderr, "entry 2:") {
		t.Errorf("the failed input is not reported on stderr with its position: %q", stderr)
	}
	if strings.Contains(stdout, "!not-base64!") || strings.Contains(stderr, "!not-base64!") {
		t.Errorf("the input was echoed back:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

func TestInspectBatchJSONIsOneArray(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	file := batchFile(t, v.UnsignedEntryXDR, "!not-base64!")

	stdout, stderr, err := runBatchCLI(t, nil, "", "inspect", "--entries", file, "--json")
	if err == nil {
		t.Fatal("a batch with a malformed line succeeded")
	}
	if stderr != "" {
		t.Errorf("stderr is not empty in JSON mode: %q", stderr)
	}
	got := decodeBatchReport(t, stdout)
	if len(got) != 2 {
		t.Fatalf("the report has %d elements, want 2", len(got))
	}
	if got[0].Entry != 1 || len(got[0].Result) == 0 || got[0].Error != "" {
		t.Errorf("element 1 = %+v, want a result for entry 1", got[0])
	}
	if got[1].Entry != 2 || got[1].Error == "" || len(got[1].Result) != 0 {
		t.Errorf("element 2 = %+v, want an error for entry 2", got[1])
	}
}

func TestBatchReadsEntriesFromStdin(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	stdout, stderr, err := runBatchCLI(t, nil, v.UnsignedEntryXDR+"\n", "inspect", "--entries", "-")
	if err != nil {
		t.Fatalf("inspect --entries - returned an error: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stdout, "entry 1:") {
		t.Errorf("stdout does not label the stdin entry:\n%s", stdout)
	}
}

func TestBatchRejectsAnEmptyFile(t *testing.T) {
	file := batchFile(t)
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	tests := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{
			name: "inspect",
			args: []string{"inspect", "--entries", file},
		},
		{
			name: "verify",
			args: []string{"verify", "--entries", file, "--network", "testnet"},
		},
		{
			name: "sign",
			env:  map[string]string{"SEED": signer.Seed()},
			args: []string{"sign", "--entries", file, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
		},
		{
			name: "diff",
			args: []string{"diff", "--before-entries", file, "--after-entries", file},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := runBatchCLI(t, tt.env, "", tt.args...)
			if err == nil {
				t.Fatalf("%v accepted an empty batch", tt.args)
			}
			if code := ExitCode(err); code != ExitUsageError {
				t.Errorf("exit code = %d, want %d", code, ExitUsageError)
			}
			if !strings.Contains(err.Error(), "contains no entries") {
				t.Errorf("err = %q, want it to say the file contains no entries", err)
			}
		})
	}
}

func TestBatchRejectsAnEnvelopeLine(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector: %v", err)
	}
	envelope := testEnvelopeXDR(t, testInvokeOperation(entry))
	file := batchFile(t, envelope)

	_, stderr, err := runBatchCLI(t, nil, "", "inspect", "--entries", file)
	if err == nil {
		t.Fatal("a batch line carrying an envelope was accepted")
	}
	// The refusal has to say how to fix it: the caller selects the entries
	// out of the envelope, because batch mode is one entry per line. In text
	// mode the per-input error goes to stderr, with its position.
	if !strings.Contains(stderr, "entry 1:") ||
		!strings.Contains(stderr, "transaction envelope carrying 1 authorization entries") {
		t.Errorf("stderr = %q, want the envelope refusal, labelled with the input's position", stderr)
	}
}

func TestBatchModeFlagRules(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	file := batchFile(t, v.UnsignedEntryXDR)
	seed := vectorKeypair(t, "soroauth-vector-signer-1").Seed()

	tests := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{
			name: "inspect entry and entries are mutually exclusive",
			args: []string{"inspect", "--entry", v.UnsignedEntryXDR, "--entries", file},
			want: "--entry and --entries are mutually exclusive",
		},
		{
			name: "verify entry and entries are mutually exclusive",
			args: []string{"verify", "--entry", v.UnsignedEntryXDR, "--entries", file, "--network", "testnet"},
			want: "--entry and --entries are mutually exclusive",
		},
		{
			name: "sign entry and entries are mutually exclusive",
			env:  map[string]string{"SEED": seed},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--entries", file, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			want: "--entry and --entries are mutually exclusive",
		},
		{
			name: "sign refuses --for on a batch",
			env:  map[string]string{"SEED": seed},
			args: []string{"sign", "--entries", file, "--for", vectorKeypair(t, "soroauth-vector-signer-1").Address(),
				"--valid-until", "1234567", "--network", "testnet", "--secret-env", "SEED"},
			want: "--for applies to a single entry",
		},
		{
			name: "verify still requires a network",
			args: []string{"verify", "--entries", file},
			want: "--network is required",
		},
		{
			name: "diff mixing single and batch flags",
			args: []string{"diff", "--before", v.UnsignedEntryXDR, "--before-entries", file, "--after-entries", file},
			want: "--before/--after and --before-entries/--after-entries are mutually exclusive",
		},
		{
			name: "diff needs both batch flags",
			args: []string{"diff", "--after-entries", file},
			want: "--before-entries is required with --after-entries",
		},
		{
			name: "diff needs both batch flags (other side)",
			args: []string{"diff", "--before-entries", file},
			want: "--after-entries is required with --before-entries",
		},
		{
			name: "diff batch reads one side from stdin at most",
			args: []string{"diff", "--before-entries", "-", "--after-entries", "-"},
			want: "only one of --before-entries and --after-entries can be read from stdin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := runBatchCLI(t, tt.env, "", tt.args...)
			if err == nil {
				t.Fatalf("%v was accepted", tt.args)
			}
			if code := ExitCode(err); code != ExitUsageError {
				t.Errorf("exit code = %d, want %d", code, ExitUsageError)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestVerifyBatchReportsPerEntryVerdicts(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	file := batchFile(t, v.SignedEntryXDR, v.UnsignedEntryXDR)

	stdout, stderr, err := runBatchCLI(t, nil, "", "verify", "--entries", file, "--network", "testnet")
	if err == nil {
		t.Fatal("a batch with an unsigned entry succeeded")
	}
	if code := ExitCode(err); code != ExitVerificationFailed {
		t.Errorf("exit code = %d, want %d", code, ExitVerificationFailed)
	}
	// A verdict is a result, not an input error, so it stays on stdout.
	if stderr != "" {
		t.Errorf("stderr is not empty: %q", stderr)
	}
	if !strings.Contains(stdout, "entry 1:") || !strings.Contains(stdout, "entry 2:") {
		t.Errorf("stdout does not label both inputs:\n%s", stdout)
	}
	// Count "VERIFIED:" at start of line for verified entries, not "NOT VERIFIED:".
	verifiedCount := 0
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "VERIFIED:") {
			verifiedCount++
		}
	}
	if verifiedCount != 1 {
		t.Errorf("the report carries %d verified verdicts, want 1:\n%s", verifiedCount, stdout)
	}
	if !strings.Contains(stdout, "NOT VERIFIED") {
		t.Errorf("the unsigned entry's verdict is missing:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "1 of 2 entries failed") {
		t.Errorf("summary = %q, want it to count 1 of 2", err)
	}

	t.Run("json", func(t *testing.T) {
		stdout, stderr, err := runBatchCLI(t, nil, "", "verify", "--entries", file, "--network", "testnet", "--json")
		if err == nil {
			t.Fatal("a batch with an unsigned entry succeeded")
		}
		if stderr != "" {
			t.Errorf("stderr is not empty in JSON mode: %q", stderr)
		}
		var elements []struct {
			Entry  int `json:"entry"`
			Result struct {
				Verified bool `json:"verified"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(stdout), &elements); err != nil {
			t.Fatalf("the report is not one JSON array: %v\n%s", err, stdout)
		}
		if len(elements) != 2 || !elements[0].Result.Verified || elements[1].Result.Verified {
			t.Errorf("verdicts = %+v, want [verified, not verified]", elements)
		}
	})

	t.Run("allow-unsigned", func(t *testing.T) {
		unsigned := batchFile(t, v.UnsignedEntryXDR)
		if _, _, err := runBatchCLI(t, nil, "", "verify", "--entries", unsigned,
			"--network", "testnet", "--allow-unsigned"); err != nil {
			t.Errorf("--allow-unsigned did not accept the batch: %v", err)
		}
	})
}

func TestVerifyBatchValidUntilIsAnAssertionPerEntry(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	file := batchFile(t, v.SignedEntryXDR)

	stdout, _, err := runBatchCLI(t, nil, "", "verify", "--entries", file,
		"--network", "testnet", "--valid-until", "424242", "--json")
	if err == nil {
		t.Fatal("a batch whose expiration disagrees with --valid-until succeeded")
	}
	if code := ExitCode(err); code != ExitVerificationFailed {
		t.Errorf("exit code = %d, want %d", code, ExitVerificationFailed)
	}
	got := decodeBatchReport(t, stdout)
	if len(got) != 1 || got[0].Code != "verification_failed" ||
		got[0].Field != "--valid-until" || got[0].ExitCode != ExitVerificationFailed {
		t.Errorf("report = %+v, want a structured expiration disagreement", got)
	}
}

func TestVerifyBatchDecodeFailureKeepsGoing(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	file := batchFile(t, v.SignedEntryXDR, "!not-base64!")

	stdout, stderr, err := runBatchCLI(t, nil, "", "verify", "--entries", file, "--network", "testnet")
	if err == nil {
		t.Fatal("a batch with a malformed line succeeded")
	}
	if code := ExitCode(err); code != ExitUsageError {
		t.Errorf("exit code = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stdout, "entry 1:") {
		t.Errorf("the good input's result is missing:\n%s", stdout)
	}
	if !strings.Contains(stderr, "entry 2:") {
		t.Errorf("the malformed input is not reported on stderr: %q", stderr)
	}
}

func TestSignBatchSignsEveryEntry(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")
	env := map[string]string{"SEED": signer.Seed()}
	file := batchFile(t, v.UnsignedEntryXDR, v.UnsignedEntryXDR)
	signArgs := []string{"sign", "--entries", file, "--valid-until", "1234567",
		"--network", "testnet", "--secret-env", "SEED"}

	stdout, stderr, err := runBatchCLI(t, env, "", signArgs...)
	if err != nil {
		t.Fatalf("sign --entries returned an error: %v (stderr %q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr is not empty: %q", stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 || lines[0] != "entry 1:" || lines[2] != "entry 2:" {
		t.Fatalf("the text output does not carry both positions:\n%s", stdout)
	}
	// Signing is deterministic, so each result must be the golden vector's
	// signed entry exactly — the same reference a single sign is held to.
	if lines[1] != v.SignedEntryXDR || lines[3] != v.SignedEntryXDR {
		t.Errorf("the batch output differs from the golden vector:\n want %s\n  got %s\n      %s",
			v.SignedEntryXDR, lines[1], lines[3])
	}

	t.Run("json", func(t *testing.T) {
		stdout, stderr, err := runBatchCLI(t, env, "", append(signArgs, "--json")...)
		if err != nil {
			t.Fatalf("sign --entries --json returned an error: %v (stderr %q)", err, stderr)
		}
		if stderr != "" {
			t.Errorf("stderr is not empty in JSON mode: %q", stderr)
		}
		var elements []struct {
			Entry  int `json:"entry"`
			Result struct {
				SignedEntry string `json:"signed_entry"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(stdout), &elements); err != nil {
			t.Fatalf("the report is not one JSON array: %v\n%s", err, stdout)
		}
		if len(elements) != 2 ||
			elements[0].Entry != 1 || elements[0].Result.SignedEntry != v.SignedEntryXDR ||
			elements[1].Entry != 2 || elements[1].Result.SignedEntry != v.SignedEntryXDR {
			t.Errorf("elements = %+v, want both entries signed to the golden vector", elements)
		}
	})
}

// TestSignBatchIsAllOrNothing is the issue's signing rule: a batch that cannot
// be fully signed produces no signed output. Both the decode path and the
// signing path are driven, and the second case signs line 1 successfully before
// line 2 is refused, so the test proves the good signature is discarded rather
// than merely never produced.
func TestSignBatchIsAllOrNothing(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")
	env := map[string]string{"SEED": signer.Seed()}

	signArgs := func(file string) []string {
		return []string{"sign", "--entries", file, "--valid-until", "1234567",
			"--network", "testnet", "--secret-env", "SEED"}
	}

	t.Run("a malformed line discards everything", func(t *testing.T) {
		file := batchFile(t, v.UnsignedEntryXDR, "!not-base64!")
		stdout, _, err := runBatchCLI(t, env, "", signArgs(file)...)
		if err == nil {
			t.Fatal("a batch with a malformed line signed")
		}
		if code := ExitCode(err); code != ExitUsageError {
			t.Errorf("exit code = %d, want %d", code, ExitUsageError)
		}
		if stdout != "" {
			t.Errorf("a failed batch wrote signed output: %q", stdout)
		}
		if !strings.Contains(err.Error(), "no signed output was written") ||
			!strings.Contains(err.Error(), "entry 2") {
			t.Errorf("err = %q, want it to say nothing was written and name entry 2", err)
		}
	})

	t.Run("a signing refusal discards everything", func(t *testing.T) {
		// Line 1 signs; line 2 is already signed, so AuthorizeEntry refuses
		// it and line 1's signature must not escape either.
		file := batchFile(t, v.UnsignedEntryXDR, v.SignedEntryXDR)
		stdout, _, err := runBatchCLI(t, env, "", signArgs(file)...)
		if err == nil {
			t.Fatal("a batch with an already-signed entry signed")
		}
		if code := ExitCode(err); code != ExitSigningRefusal {
			t.Errorf("exit code = %d, want %d", code, ExitSigningRefusal)
		}
		if stdout != "" {
			t.Errorf("a failed batch wrote signed output: %q", stdout)
		}
		if !strings.Contains(err.Error(), "no signed output was written") ||
			!strings.Contains(err.Error(), "entry 2") ||
			!strings.Contains(err.Error(), "already signed") {
			t.Errorf("err = %q, want it to name entry 2 and the refusal", err)
		}
	})

	t.Run("json reports one error object", func(t *testing.T) {
		file := batchFile(t, v.UnsignedEntryXDR, "!not-base64!")
		stdout, stderr, err := runBatchCLI(t, env, "", append(signArgs(file), "--json")...)
		if err == nil {
			t.Fatal("a batch with a malformed line signed")
		}
		if stderr != "" {
			t.Errorf("stderr is not empty in JSON mode: %q", stderr)
		}
		var out struct {
			Error         string `json:"error"`
			SchemaVersion int    `json:"schema_version"`
			Code          string `json:"code"`
			Message       string `json:"message"`
			Field         string `json:"field"`
			ExitCode      int    `json:"exit_code"`
		}
		if jsonErr := json.Unmarshal([]byte(stdout), &out); jsonErr != nil {
			t.Fatalf("a failed batch must be a single JSON error object: %v\n%s", jsonErr, stdout)
		}
		if out.SchemaVersion != jsonErrorSchemaVersion || out.Code != "usage_error" ||
			out.Message == "" || out.Field != "--entries" || out.ExitCode != ExitUsageError ||
			out.Error != out.Message {
			t.Errorf("error object does not satisfy the versioned schema: %+v", out)
		}
	})
}

func TestDiffBatchPairsEntriesByPosition(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	// Pair 1 is a plain signing step; pair 2 has a stale signature.
	before := batchFile(t, v.UnsignedEntryXDR, v.SignedEntryXDR)
	after := batchFile(t, v.SignedEntryXDR, staleEntry(t, v))

	stdout, stderr, err := runBatchCLI(t, nil, "", "diff", "--before-entries", before, "--after-entries", after)
	if err == nil {
		t.Fatal("a batch with a stale signature succeeded")
	}
	if code := ExitCode(err); code != ExitVerificationFailed {
		t.Errorf("exit code = %d, want %d", code, ExitVerificationFailed)
	}
	// A stale signature is a verdict, so it stays a stdout result.
	if stderr != "" {
		t.Errorf("stderr is not empty: %q", stderr)
	}
	if !strings.Contains(stdout, "entry 1:") || !strings.Contains(stdout, "entry 2:") {
		t.Errorf("stdout does not label both pairs:\n%s", stdout)
	}
	if !strings.Contains(stdout, "stale signatures") {
		t.Errorf("the stale-signature section is missing:\n%s", stdout)
	}

	t.Run("json", func(t *testing.T) {
		stdout, stderr, err := runBatchCLI(t, nil, "",
			"diff", "--before-entries", before, "--after-entries", after, "--json")
		if err == nil {
			t.Fatal("a batch with a stale signature succeeded")
		}
		if stderr != "" {
			t.Errorf("stderr is not empty in JSON mode: %q", stderr)
		}
		var elements []struct {
			Entry  int `json:"entry"`
			Result struct {
				StaleSignatures []string `json:"stale_signatures"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(stdout), &elements); err != nil {
			t.Fatalf("the report is not one JSON array: %v\n%s", err, stdout)
		}
		if len(elements) != 2 || elements[0].Entry != 1 || len(elements[0].Result.StaleSignatures) != 0 {
			t.Errorf("element 1 = %+v, want a clean verdict", elements)
		}
		if len(elements) < 2 || elements[1].Entry != 2 || len(elements[1].Result.StaleSignatures) != 1 {
			t.Errorf("elements = %+v, want pair 2 to carry one stale signature", elements)
		}
	})
}

func TestDiffBatchRequiresEqualCounts(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	before := batchFile(t, v.UnsignedEntryXDR, v.UnsignedEntryXDR)
	after := batchFile(t, v.SignedEntryXDR)

	_, _, err := runBatchCLI(t, nil, "", "diff", "--before-entries", before, "--after-entries", after)
	if err == nil {
		t.Fatal("diff accepted two batch files with different entry counts")
	}
	if code := ExitCode(err); code != ExitUsageError {
		t.Errorf("exit code = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(err.Error(), "pairwise in order") {
		t.Errorf("err = %q, want it to explain the pairing rule", err)
	}
}

func TestDiffBatchNamesTheSideThatFailed(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	before := batchFile(t, "!not-base64!")
	after := batchFile(t, v.UnsignedEntryXDR)

	stdout, _, err := runBatchCLI(t, nil, "", "diff",
		"--before-entries", before, "--after-entries", after, "--json")
	if err == nil {
		t.Fatal("diff accepted a malformed before side")
	}
	got := decodeBatchReport(t, stdout)
	if len(got) != 1 || got[0].Field != "--before-entries" ||
		got[0].SchemaVersion != jsonErrorSchemaVersion || got[0].Code != "usage_error" {
		t.Errorf("report = %+v, want the error to name the side that failed", got)
	}
}

func TestReadBatchEntriesSkipsBlankLines(t *testing.T) {
	inputs, err := readBatchEntries("--entries", "-", strings.NewReader("\n  \nfirst\n\nsecond\n"))
	if err != nil {
		t.Fatalf("reading the batch: %v", err)
	}
	if len(inputs) != 2 {
		t.Fatalf("read %d inputs, want 2", len(inputs))
	}
	// The lines are not valid entries, but the numbering is what this test
	// pins: blank lines do not consume an index and the first non-blank line
	// is entry 1.
	if inputs[0].Index != 1 || inputs[1].Index != 2 {
		t.Errorf("indices = [%d %d], want [1 2]", inputs[0].Index, inputs[1].Index)
	}
	if inputs[0].Err == nil || inputs[1].Err == nil {
		t.Errorf("non-base64 lines did not produce per-input errors")
	}
}

func TestReadBatchEntriesRefusesAnOverlongLine(t *testing.T) {
	inputs, err := readBatchEntries("--entries", "-", strings.NewReader(strings.Repeat("A", maxBatchLine+1)))
	if err != nil {
		t.Fatalf("the read itself failed: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("read %d inputs, want 1 carrying the scan failure", len(inputs))
	}
	if inputs[0].Err == nil || !strings.Contains(inputs[0].Err.Error(), "line limit") {
		t.Errorf("input error = %v, want the overlong-line refusal", inputs[0].Err)
	}
}
