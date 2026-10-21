package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONErrorCodesCoverEverySentinel(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "errors.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsing library sentinel declarations: %v", err)
	}
	declared := 0
	for _, declaration := range source.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			values, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range values.Names {
				if strings.HasPrefix(name.Name, "Err") {
					declared++
				}
			}
		}
	}
	if declared != len(sentinelJSONErrors) {
		t.Fatalf("errors.go declares %d sentinels but JSON maps %d; add a stable machine code for each sentinel",
			declared, len(sentinelJSONErrors))
	}

	seen := make(map[string]bool, len(sentinelJSONErrors))
	for _, sentinel := range sentinelJSONErrors {
		t.Run(sentinel.code, func(t *testing.T) {
			if sentinel.code == "" || seen[sentinel.code] {
				t.Fatalf("empty or duplicate machine code %q", sentinel.code)
			}
			seen[sentinel.code] = true
			fields := machineError(sentinel.err)
			if fields.Code != sentinel.code {
				t.Errorf("code = %q, want %q", fields.Code, sentinel.code)
			}
			if fields.Message != sentinel.message {
				t.Errorf("message = %q, want safe sentinel message %q", fields.Message, sentinel.message)
			}
			if fields.SchemaVersion != jsonErrorSchemaVersion {
				t.Errorf("schema version = %d, want %d", fields.SchemaVersion, jsonErrorSchemaVersion)
			}
		})
	}
}

func TestEveryJSONSubcommandUsesVersionedErrorSchema(t *testing.T) {
	oversized := filepath.Join(t.TempDir(), "oversized.wasm")
	if err := os.WriteFile(oversized, []byte("too large"), 0o600); err != nil {
		t.Fatal(err)
	}

	argsByCommand := map[string][]string{
		"payload":       {"--entry", "not-base64", "--valid-until", "1", "--network", "testnet", "--json"},
		"sign":          {"--json"},
		"simulate":      {"--json"},
		"submit":        {"--json"},
		"delegates":     {"--json"},
		"inspect":       {"--entry", "not-base64", "--json"},
		"tree":          {"--entry", "not-base64", "--json"},
		"doctor":        {"--rpc-url", "http://127.0.0.1:0", "--json"},
		"cross-compile": {"--targets", "invalid/target", "--json"},
		"verify":        {"--entry", "not-base64", "--json"},
		"diff":          {"--json"},
		"completions":   {"--json"},
		"man":           {"--out", filepath.Join(t.TempDir(), "soroauth.1"), "--json"},
		"wasm-budget":   {"--out", oversized, "--budget", "1", "--json"},
	}

	for _, spec := range commandSpecs {
		t.Run(spec.Name, func(t *testing.T) {
			hasJSON := false
			for _, flag := range spec.Flags {
				hasJSON = hasJSON || flag.Name == "json"
			}
			if !hasJSON {
				t.Skip("subcommand intentionally has no --json mode")
			}
			args, ok := argsByCommand[spec.Name]
			if !ok {
				t.Fatalf("no failing JSON invocation registered for %q", spec.Name)
			}
			stdout, stderr, err := runCLI(t, append([]string{spec.Name}, args...)...)
			if err == nil {
				t.Fatalf("failing invocation succeeded; stdout=%q", stdout)
			}
			if stderr != "" {
				t.Errorf("JSON error also wrote to stderr: %q", stderr)
			}

			var output jsonErrorOutput
			if decodeErr := json.Unmarshal([]byte(stdout), &output); decodeErr != nil {
				t.Fatalf("stdout is not a versioned JSON error: %v\nstdout: %q", decodeErr, stdout)
			}
			if output.SchemaVersion != jsonErrorSchemaVersion {
				t.Errorf("schema_version = %d, want %d", output.SchemaVersion, jsonErrorSchemaVersion)
			}
			if output.Code == "" || output.Message == "" || output.Field == "" {
				t.Errorf("error is missing code, message, or offending field: %+v", output)
			}
			if output.Error != output.Message {
				t.Errorf("compatibility error = %q, message = %q", output.Error, output.Message)
			}
			if output.ExitCode != ExitCode(err) {
				t.Errorf("JSON exit_code = %d, process exit code = %d", output.ExitCode, ExitCode(err))
			}
			if output.ExitCode == ExitOK {
				t.Errorf("error payload carries success exit code: %+v", output)
			}
		})
	}

}

func TestJSONErrorNeverEchoesInputOrCredentialMaterial(t *testing.T) {
	const (
		entryMarker  = "ENTRY_MUST_NOT_LEAK"
		secretMarker = "SECRET_MUST_NOT_LEAK"
		keyMarker    = "KEY_MUST_NOT_LEAK"
	)
	err := newErrorf(ExitUsageError, "entry %s secret %s key %s", entryMarker, secretMarker, keyMarker)
	stdout, stderr := new(strings.Builder), new(strings.Builder)
	gotErr := writeJSONError(stdout, true, err)
	if gotErr == nil {
		t.Fatal("writeJSONError returned nil")
	}
	if stderr.Len() != 0 {
		t.Fatalf("JSON error unexpectedly wrote to stderr: %q", stderr.String())
	}
	for _, marker := range []string{entryMarker, secretMarker, keyMarker} {
		if strings.Contains(stdout.String(), marker) {
			t.Errorf("JSON error contains sensitive input %q: %s", marker, stdout.String())
		}
	}
	var output jsonErrorOutput
	if err := json.Unmarshal([]byte(stdout.String()), &output); err != nil {
		t.Fatalf("decoding JSON error: %v", err)
	}
	if output.Code != "usage_error" || output.ExitCode != ExitUsageError {
		t.Errorf("unexpected structured error: %+v", output)
	}
}

func TestJSONErrorFieldCanBeAttachedWithoutChangingHumanText(t *testing.T) {
	err := withField("--entry", newErrorf(ExitUsageError, "invalid value: %s", "private-input"))
	if got := err.Error(); got != "invalid value: private-input" {
		t.Fatalf("human error changed: %q", got)
	}
	fields := machineError(err)
	if fields.Field != "--entry" {
		t.Errorf("field = %q, want --entry", fields.Field)
	}
	if strings.Contains(fields.Message, "private-input") {
		t.Errorf("machine message contains input: %q", fields.Message)
	}
	if ExitCode(err) != fields.ExitCode {
		t.Errorf("exit code = %d, payload exit code = %d", ExitCode(err), fields.ExitCode)
	}
}

func TestBatchJSONFailureCarriesStructuredErrorFields(t *testing.T) {
	run := newBatchRun(1)
	run.fail(1, withField("--entry", newErrorf(ExitUsageError, "bad entry: %s", "secret-blob")))
	var stdout strings.Builder
	err := run.finish(&stdout, true)
	if ExitCode(err) != ExitUsageError {
		t.Fatalf("exit code = %d, want %d", ExitCode(err), ExitUsageError)
	}

	var result []struct {
		Entry         int    `json:"entry"`
		Error         string `json:"error"`
		SchemaVersion int    `json:"schema_version"`
		Code          string `json:"code"`
		Message       string `json:"message"`
		Field         string `json:"field"`
		ExitCode      int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decoding batch output: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d results, want 1", len(result))
	}
	got := result[0]
	if got.SchemaVersion != jsonErrorSchemaVersion || got.Code != "usage_error" ||
		got.Message == "" || got.Field != "--entry" || got.ExitCode != ExitUsageError {
		t.Errorf("incomplete batch error schema: %+v", got)
	}
	if got.Error != got.Message || strings.Contains(stdout.String(), "secret-blob") {
		t.Errorf("batch error is not safe or compatibility text differs: %+v; output=%q", got, stdout.String())
	}
}

func TestMachineErrorFallbackCodeMatchesExitClass(t *testing.T) {
	tests := []struct {
		exit int
		code string
	}{
		{ExitGeneralError, "command_failed"},
		{ExitUsageError, "usage_error"},
		{ExitSigningRefusal, "signing_refused"},
		{ExitVerificationFailed, "verification_failed"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.exit), func(t *testing.T) {
			fields := machineError(newErrorf(tt.exit, "error contains private material"))
			if fields.Code != tt.code || fields.ExitCode != tt.exit {
				t.Errorf("machine error = %+v, want code %q and exit %d", fields, tt.code, tt.exit)
			}
		})
	}
}
