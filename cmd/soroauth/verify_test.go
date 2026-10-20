package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// signedVectorEntry returns the signed form of a golden vector's unsigned
// entry, signed by the vector's first signer, so the CLI is exercised against
// real reference-produced entry bytes rather than invented ones.
func signedVectorEntry(t *testing.T, name string) (signed string, raw vectorFile) {
	t.Helper()
	v := loadVector(t, name)

	entry, err := soroauth.DecodeAuthorizationEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}

	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-vector-signer-1")))
	if err != nil {
		t.Fatalf("deriving the vector signer: %v", err)
	}

	signedEntry, err := soroauth.AuthorizeEntry(context.Background(), entry,
		soroauth.NewEd25519Signer(kp), v.ValidUntilLedger, v.NetworkPassphrase)
	if err != nil {
		t.Fatalf("signing the vector entry: %v", err)
	}

	encoded, err := xdr.MarshalBase64(signedEntry)
	if err != nil {
		t.Fatalf("encoding the signed entry: %v", err)
	}
	return encoded, v
}

func TestVerifySubcommandAcceptsASignedEntry(t *testing.T) {
	entry, v := signedVectorEntry(t, "v2_single_testnet")

	stdout, _, err := runCLI(t, "verify", "--entry", entry, "--network", v.NetworkPassphrase)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !strings.Contains(stdout, "VERIFIED") {
		t.Errorf("stdout does not report a verified node: %q", stdout)
	}
	if !strings.Contains(stdout, "credential nodes verified") {
		t.Errorf("stdout does not carry the verified result line: %q", stdout)
	}
}

func TestVerifySubcommandRejectsATamperedExpiration(t *testing.T) {
	entry, v := signedVectorEntry(t, "v2_single_testnet")

	// Bump the expiration without re-signing: the payload the entry now
	// commits to is different from the one signed over, so the stored
	// signature must come back invalid rather than verified.
	var parsed xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(entry, &parsed); err != nil {
		t.Fatalf("decoding the signed entry: %v", err)
	}
	parsed.Credentials.AddressV2.SignatureExpirationLedger = xdr.Uint32(v.ValidUntilLedger + 1)
	tampered, err := xdr.MarshalBase64(parsed)
	if err != nil {
		t.Fatalf("encoding the tampered entry: %v", err)
	}

	stdout, _, err := runCLI(t, "verify", "--entry", tampered, "--network", v.NetworkPassphrase)
	if err == nil {
		t.Fatal("verify accepted an entry whose signature does not cover its expiration")
	}
	if code := ExitCode(err); code != ExitVerificationFailed {
		t.Errorf("exit code = %d, want %d", code, ExitVerificationFailed)
	}
	if !strings.Contains(stdout, "invalid") {
		t.Errorf("stdout does not report an invalid node: %q", stdout)
	}
}

func TestVerifySubcommandUnsignedNodeAndAllowUnsigned(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	stdout, _, err := runCLI(t, "verify", "--entry", v.UnsignedEntryXDR, "--network", v.NetworkPassphrase)
	if err == nil {
		t.Fatal("verify accepted an unsigned entry without --allow-unsigned")
	}
	if code := ExitCode(err); code != ExitVerificationFailed {
		t.Errorf("exit code = %d, want %d", code, ExitVerificationFailed)
	}
	if !strings.Contains(stdout, "unsigned") {
		t.Errorf("stdout does not report an unsigned node: %q", stdout)
	}

	_, _, err = runCLI(t, "verify", "--entry", v.UnsignedEntryXDR, "--network", v.NetworkPassphrase, "--allow-unsigned")
	if err != nil {
		t.Fatalf("verify refused an unsigned entry with --allow-unsigned: %v", err)
	}
}

func TestVerifySubcommandJSON(t *testing.T) {
	entry, v := signedVectorEntry(t, "v2_single_testnet")

	stdout, _, err := runCLI(t, "verify", "--entry", entry, "--network", v.NetworkPassphrase, "--json")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	var out struct {
		CredentialType string `json:"credential_type"`
		Verified       bool   `json:"verified"`
		Nodes          []struct {
			Address string `json:"address"`
			Verdict string `json:"verdict"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decoding the JSON report: %v\n%s", err, stdout)
	}
	if !out.Verified {
		t.Errorf("verified = false in the JSON report: %s", stdout)
	}
	if out.CredentialType != soroauth.CredentialTypeAddressV2 {
		t.Errorf("credential_type = %q, want %q", out.CredentialType, soroauth.CredentialTypeAddressV2)
	}
	if len(out.Nodes) != 1 || out.Nodes[0].Verdict != string(soroauth.VerdictVerified) {
		t.Errorf("nodes = %+v, want one verified node", out.Nodes)
	}
}

func TestVerifySubcommandValidUntilAssertion(t *testing.T) {
	entry, v := signedVectorEntry(t, "v2_single_testnet")

	_, _, err := runCLI(t, "verify", "--entry", entry, "--network", v.NetworkPassphrase,
		"--valid-until", "1")
	if err == nil {
		t.Fatal("verify accepted a --valid-until that disagrees with the entry")
	}
	if code := ExitCode(err); code != ExitVerificationFailed {
		t.Errorf("exit code = %d, want %d", code, ExitVerificationFailed)
	}
}

func TestVerifySubcommandRequiresNetwork(t *testing.T) {
	entry, _ := signedVectorEntry(t, "v2_single_testnet")

	if _, _, err := runCLI(t, "verify", "--entry", entry); err == nil {
		t.Fatal("verify succeeded without --network")
	} else if code := ExitCode(err); code != ExitUsageError {
		t.Errorf("exit code = %d, want %d", code, ExitUsageError)
	}
}

func TestVerifySubcommandSourceAccount(t *testing.T) {
	v := loadVector(t, "source_account_testnet")

	stdout, _, err := runCLI(t, "verify", "--entry", v.UnsignedEntryXDR, "--network", v.NetworkPassphrase)
	if err != nil {
		t.Fatalf("verify refused a source-account entry: %v", err)
	}
	if !strings.Contains(stdout, "source_account") {
		t.Errorf("stdout does not name the source-account arm: %q", stdout)
	}
}
