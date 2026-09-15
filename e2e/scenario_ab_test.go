//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// transferAmount is 1 XLM in stroops. Small enough that friendbot funding
// covers many runs.
const transferAmount = 10_000_000

// runTransfer drives the full flow §5.10 describes: simulate in record mode,
// sign with soroauth, re-simulate in enforce mode with the signed entries so
// the resources account for the signatures, assemble, sign the envelope as the
// payer, submit, and poll.
func runTransfer(
	t *testing.T,
	h *harness,
	payer *keypair.Full,
	op txnbuild.InvokeHostFunction,
	signers []soroauth.Signer,
	useUpgradedAuth bool,
	transform func(t *testing.T, entries []xdr.SorobanAuthorizationEntry) []xdr.SorobanAuthorizationEntry,
) submission {
	t.Helper()

	// 1. record
	recordTx := h.build(t, h.account(t, payer.Address()), op)
	recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, useUpgradedAuth)

	// 2. sign, with an optional transformation between recording and signing
	validUntil, err := soroauth.ExpirationAfter(h.latestLedger(t), 1000)
	if err != nil {
		t.Fatalf("computing the expiration ledger: %v", err)
	}

	if len(recorded.Results) != 1 {
		t.Fatalf("simulation returned %d results, want 1", len(recorded.Results))
	}
	recordedAuth := recorded.Results[0].AuthXDR
	if recordedAuth == nil {
		t.Fatal("simulation recorded no authorization entries; the transfer would not need soroauth at all")
	}

	entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*recordedAuth))
	for i, encoded := range *recordedAuth {
		var entry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
			t.Fatalf("decoding recorded auth entry %d: %v", i, err)
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		t.Fatal("simulation recorded no authorization entries")
	}
	if transform != nil {
		entries = transform(t, entries)
	}

	signedEntries, err := soroauth.AuthorizeAll(context.Background(), entries, signers, validUntil, h.passphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	for i, entry := range signedEntries {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting signed entry %d: %v", i, err)
		}
		t.Logf("entry %d: %s address=%s signed=%v", i, info.CredentialType, info.Address, info.TopLevelSigned)
	}

	// 3. enforce, carrying the signed entries so the fee covers them
	op.Auth = signedEntries
	enforceTx := h.build(t, h.account(t, payer.Address()), op)
	enforced := h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)

	// 4. assemble with the enforcing pass's resources, 5. sign as the payer
	finalTx := h.assemble(t, h.account(t, payer.Address()), op, enforced)
	finalTx, err = finalTx.Sign(h.passphrase, payer)
	if err != nil {
		t.Fatalf("signing the envelope as the payer: %v", err)
	}

	// 6. send and poll
	return h.send(t, finalTx)
}

// TestScenarioA proves the legacy SOROBAN_CREDENTIALS_ADDRESS arm is accepted
// by a live host: a payer submits a transfer of someone else's XLM, authorized
// only by that someone's soroauth signature.
func TestScenarioA(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	from := h.newAccount(t, "sender A")
	to := h.newAccount(t, "recipient B")

	op := h.transferOp(t, scAddressOf(t, from.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	result := runTransfer(t, h, payer, op,
		[]soroauth.Signer{soroauth.NewEd25519Signer(from)},
		false, nil)

	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("arm:     %s", result.Arm)
	t.Logf("link:    %s%s", explorerBaseURL, result.Hash)

	record(scenarioResult{
		ID:        "A",
		Name:      "legacy address credentials accepted live",
		Proves:    "A SOROBAN_CREDENTIALS_ADDRESS entry signed by soroauth is accepted by the host.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: []string{
			"Payer and sender are different accounts, so the transfer cannot fall back to source-account auth.",
		},
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario A failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddress" {
		t.Errorf("submitted envelope carried arm %q, want the legacy address arm", result.Arm)
	}
}

// TestScenarioB proves the CAP-71 SOROBAN_CREDENTIALS_ADDRESS_V2 arm is
// accepted live. It asks simulation for V2 first, and upgrades locally if the
// RPC did not provide it, reporting which of the two actually happened.
func TestScenarioB(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	from := h.newAccount(t, "sender A")
	to := h.newAccount(t, "recipient B")

	op := h.transferOp(t, scAddressOf(t, from.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	var route string
	transform := func(t *testing.T, entries []xdr.SorobanAuthorizationEntry) []xdr.SorobanAuthorizationEntry {
		t.Helper()

		recordedArm := entries[0].Credentials.Type.String()
		if entries[0].Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
			route = "simulation returned AddressV2 directly (UseUpgradedAuth was honoured)"
			t.Log(route)
			return entries
		}

		route = "simulation returned " + recordedArm + "; upgraded locally with soroauth.UpgradeToV2"
		t.Log(route)

		upgraded := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))
		for i, entry := range entries {
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
				upgraded = append(upgraded, entry)
				continue
			}
			converted, err := soroauth.UpgradeToV2(entry)
			if err != nil {
				t.Fatalf("upgrading entry %d: %v", i, err)
			}
			upgraded = append(upgraded, converted)
		}
		return upgraded
	}

	result := runTransfer(t, h, payer, op,
		[]soroauth.Signer{soroauth.NewEd25519Signer(from)},
		true, transform)

	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("arm:     %s", result.Arm)
	t.Logf("route:   %s", route)
	t.Logf("link:    %s%s", explorerBaseURL, result.Hash)

	record(scenarioResult{
		ID:        "B",
		Name:      "CAP-71 address_v2 credentials accepted live",
		Proves:    "A SOROBAN_CREDENTIALS_ADDRESS_V2 entry, whose payload binds the signer address, is accepted by the host.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes:     []string{route},
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario B failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddressV2" {
		t.Errorf("submitted envelope carried arm %q, want the address_v2 arm", result.Arm)
	}
}
