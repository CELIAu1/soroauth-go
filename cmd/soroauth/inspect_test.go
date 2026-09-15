package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// report mirrors soroauth.EntryInfo for decoding the CLI's JSON output, so the
// test reads what a consumer of the command would actually receive.
type report struct {
	CredentialType   string `json:"credential_type"`
	AddressBound     bool   `json:"address_bound"`
	Address          string `json:"address"`
	Nonce            int64  `json:"nonce"`
	ValidUntilLedger uint32 `json:"valid_until_ledger"`
	TopLevelSigned   bool   `json:"top_level_signed"`
	Delegates        []struct {
		Address string `json:"address"`
		Signed  bool   `json:"signed"`
		Nested  []struct {
			Address string `json:"address"`
			Signed  bool   `json:"signed"`
		} `json:"nested"`
	} `json:"delegates"`
	RootContract   string `json:"root_contract"`
	RootFunction   string `json:"root_function"`
	SubInvocations int    `json:"sub_invocations"`
}

func inspectEntry(t *testing.T, entryXDR string) report {
	t.Helper()
	stdout, _, err := runCLI(t, "inspect", "--entry", entryXDR)
	if err != nil {
		t.Fatalf("inspect returned an error: %v", err)
	}
	var got report
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("the output is not valid JSON: %v\n%s", err, stdout)
	}
	return got
}

func TestInspectReportsAV2Entry(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	got := inspectEntry(t, v.UnsignedEntryXDR)

	if got.CredentialType != "address_v2" {
		t.Errorf("credential_type is %q, want address_v2", got.CredentialType)
	}
	if !got.AddressBound {
		t.Error("address_bound is false for a V2 entry")
	}
	if got.TopLevelSigned {
		t.Error("top_level_signed is true for an unsigned entry")
	}
	if got.RootFunction != "transfer" {
		t.Errorf("root_function is %q, want transfer", got.RootFunction)
	}
	if !strings.HasPrefix(got.RootContract, "C") {
		t.Errorf("root_contract is %q, want a C… address", got.RootContract)
	}
	if !strings.HasPrefix(got.Address, "G") {
		t.Errorf("address is %q, want a G… address", got.Address)
	}
}

// TestInspectShowsWhichNodesAreSigned is what the subcommand is for: checking
// before submission that an entry is signed where it should be.
func TestInspectShowsWhichNodesAreSigned(t *testing.T) {
	v := loadVector(t, "delegates_unsorted_with_nested")

	unsigned := inspectEntry(t, v.UnsignedEntryXDR)
	if unsigned.CredentialType != "address_with_delegates" {
		t.Fatalf("credential_type is %q, want address_with_delegates", unsigned.CredentialType)
	}
	if !unsigned.AddressBound {
		t.Error("address_bound is false for the delegates arm")
	}
	if len(unsigned.Delegates) != 3 {
		t.Fatalf("got %d delegates, want 3", len(unsigned.Delegates))
	}
	for _, node := range unsigned.Delegates {
		if node.Signed {
			t.Errorf("%s is reported as signed in the unsigned entry", node.Address)
		}
	}

	var nestedSeen int
	for _, node := range unsigned.Delegates {
		nestedSeen += len(node.Nested)
	}
	if nestedSeen != 1 {
		t.Errorf("got %d nested delegates, want 1", nestedSeen)
	}

	// The recorded signed entry has every delegate filled in, and the
	// account's own node deliberately left Void.
	signedVector := loadFullVector(t, "delegates_unsorted_with_nested")
	signed := inspectEntry(t, signedVector)
	if signed.TopLevelSigned {
		t.Error("top_level_signed is true, but the account never signed this entry")
	}
	for _, node := range signed.Delegates {
		if !node.Signed {
			t.Errorf("%s is reported as unsigned in the fully signed entry", node.Address)
		}
		for _, inner := range node.Nested {
			if !inner.Signed {
				t.Errorf("nested %s is reported as unsigned", inner.Address)
			}
		}
	}
	if signed.ValidUntilLedger != 1234567 {
		t.Errorf("valid_until_ledger is %d, want 1234567", signed.ValidUntilLedger)
	}
}

func TestInspectReportsSubInvocations(t *testing.T) {
	v := loadVector(t, "v2_sub_invocations")
	got := inspectEntry(t, v.UnsignedEntryXDR)

	// The tree is swap -> approve -> {deep_one, deep_two}: three descendants.
	if got.SubInvocations != 3 {
		t.Errorf("sub_invocations is %d, want 3", got.SubInvocations)
	}
	if got.RootFunction != "swap" {
		t.Errorf("root_function is %q, want swap", got.RootFunction)
	}
}

func TestInspectReportsACreateContractEntry(t *testing.T) {
	v := loadVector(t, "v2_create_contract")
	got := inspectEntry(t, v.UnsignedEntryXDR)

	if got.RootContract != "" || got.RootFunction != "" {
		t.Errorf("a create-contract entry reported contract %q and function %q, want neither",
			got.RootContract, got.RootFunction)
	}
	if got.Nonce != 9223372036854775807 {
		t.Errorf("nonce is %d, want the recorded 2^63-1", got.Nonce)
	}
}

func TestInspectReportsANegativeNonce(t *testing.T) {
	v := loadVector(t, "legacy_negative_nonce")
	got := inspectEntry(t, v.UnsignedEntryXDR)

	if got.Nonce >= 0 {
		t.Errorf("nonce is %d, want the recorded negative value", got.Nonce)
	}
	if got.CredentialType != "address" {
		t.Errorf("credential_type is %q, want address", got.CredentialType)
	}
	if got.AddressBound {
		t.Error("address_bound is true for a legacy entry")
	}
}

func TestInspectRejects(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{
			name:    "no entry",
			args:    []string{"inspect"},
			wantMsg: "--entry is required",
		},
		{
			name:    "malformed entry",
			args:    []string{"inspect", "--entry", "not-base64"},
			wantMsg: "decoding --entry",
		},
		{
			name:    "unknown flag",
			args:    []string{"inspect", "--nope"},
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
