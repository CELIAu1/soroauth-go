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

// vectorFile is the subset of a golden vector the CLI tests need. The CLI is
// exercised against the same committed vectors the library is proven with, so
// the tests use real entries rather than ones invented here.
type vectorFile struct {
	Name              string `json:"name"`
	NetworkPassphrase string `json:"network_passphrase"`
	ValidUntilLedger  uint32 `json:"valid_until_ledger"`
	PreWrapEntryXDR   string `json:"pre_wrap_entry_xdr"`
	UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
	PreimageXDR       string `json:"preimage_xdr"`
	PayloadHex        string `json:"payload_hex"`
	Delegates         []struct {
		Label   string `json:"label"`
		Address string `json:"address"`
	} `json:"delegates"`
}

func loadVector(t *testing.T, name string) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors", name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return v
}

// runCLI drives the dispatcher and captures both streams. The environment is
// empty unless a test supplies one with runCLIEnv.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return runCLIEnv(t, nil, args...)
}

// runCLIEnv drives the dispatcher with a fake environment, so no test ever
// mutates the real one or leaves a seed in it.
func runCLIEnv(t *testing.T, env map[string]string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = run(args, &out, &errOut, func(key string) string { return env[key] })
	return out.String(), errOut.String(), err
}

func TestRunWithoutACommand(t *testing.T) {
	stdout, stderr, err := runCLI(t)
	if err == nil {
		t.Fatal("running with no command succeeded")
	}
	if stdout != "" {
		t.Errorf("usage went to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr does not carry the usage text: %q", stderr)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	_, stderr, err := runCLI(t, "frobnicate")
	if err == nil {
		t.Fatal("an unknown command succeeded")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not name the unknown command", err)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Error("stderr does not carry the usage text")
	}
}

func TestRunHelp(t *testing.T) {
	stdout, _, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("help returned an error: %v", err)
	}
	if !strings.Contains(stdout, "usage:") {
		t.Errorf("help did not print the usage text: %q", stdout)
	}
}

func TestResolveNetwork(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "testnet", value: "testnet", want: "Test SDF Network ; September 2015"},
		{name: "public", value: "public", want: "Public Global Stellar Network ; September 2015"},
		{name: "a literal passphrase", value: "Standalone Network ; February 2017", want: "Standalone Network ; February 2017"},
		{name: "empty is an error", value: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveNetwork(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveNetwork(%q) succeeded, returning %q", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveNetwork(%q) returned an error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPayloadMatchesTheGoldenVector(t *testing.T) {
	// Vector 6 is the delegates case, so this also covers the address-bound
	// preimage rather than only the simple one.
	v := loadVector(t, "delegates_unsorted_with_nested")

	stdout, _, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet")
	if err != nil {
		t.Fatalf("payload returned an error: %v", err)
	}

	if !strings.Contains(stdout, v.PreimageXDR) {
		t.Errorf("output does not carry the recorded preimage\n want %s\n  got %s", v.PreimageXDR, stdout)
	}
	if !strings.Contains(stdout, v.PayloadHex) {
		t.Errorf("output does not carry the recorded payload\n want %s\n  got %s", v.PayloadHex, stdout)
	}
}

func TestPayloadRejects(t *testing.T) {
	v := loadVector(t, "delegates_unsorted_with_nested")

	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{
			name:    "no entry",
			args:    []string{"payload", "--valid-until", "1", "--network", "testnet"},
			wantMsg: "--entry is required",
		},
		{
			name:    "malformed entry",
			args:    []string{"payload", "--entry", "not-base64", "--valid-until", "1", "--network", "testnet"},
			wantMsg: "decoding --entry",
		},
		{
			name:    "no network",
			args:    []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "1"},
			wantMsg: "--network is required",
		},
		{
			name:    "zero valid-until",
			args:    []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "0", "--network", "testnet"},
			wantMsg: "--valid-until is required",
		},
		{
			name:    "unknown flag",
			args:    []string{"payload", "--nope"},
			wantMsg: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLI(t, tt.args...)
			if err == nil {
				t.Fatalf("the command succeeded, printing %q", stdout)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if stdout != "" {
				t.Errorf("a failing command wrote to stdout: %q", stdout)
			}
		})
	}
}

// TestPayloadRefusesSourceAccountEntries: there is nothing to sign for that
// arm, and printing a payload for it would invite a caller to sign something
// meaningless.
func TestPayloadRefusesSourceAccountEntries(t *testing.T) {
	// A source-account entry is the shortest legal entry: credential type 0
	// followed by the invocation. Build it by hand from a vector's invocation
	// rather than inventing XDR here.
	_, _, err := runCLI(t, "payload",
		"--entry", sourceAccountEntryFromVector(t),
		"--valid-until", "1234567",
		"--network", "testnet")
	if err == nil {
		t.Fatal("payload accepted a source-account entry")
	}
	if !strings.Contains(err.Error(), "source-account") {
		t.Errorf("error %q does not explain the source-account case", err)
	}
}

// sourceAccountEntryFromVector rebuilds a vector's entry with source-account
// credentials, so the test uses a real invocation tree.
func sourceAccountEntryFromVector(t *testing.T) string {
	t.Helper()
	v := loadVector(t, "v2_single_testnet")

	entry, err := decodeEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	entry.Credentials = xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
	}
	encoded, err := encodeEntry(entry)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return encoded
}

// loadFullVector returns a vector's recorded signed entry.
func loadFullVector(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors", name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var v struct {
		SignedEntryXDR string `json:"signed_entry_xdr"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return v.SignedEntryXDR
}
