//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// delegatesFlow runs the CAP-71-01 two-simulation flow for a delegates entry:
// record, wrap the recorded entry with WithDelegates, sign each delegate with
// ForAddress, then enforce, assemble, submit.
//
// delegatesToAttach is what goes into the entry. signers is who actually signs.
// Scenario E gives an address in the first that is missing from the account's
// registered set, which is the whole point of that scenario.
func delegatesFlow(
	t *testing.T,
	h *harness,
	payer *keypair.Full,
	contract string,
	to *keypair.Full,
	delegatesToAttach []string,
	signers []*keypair.Full,
	expectFailure bool,
) submission {
	t.Helper()

	op := h.transferOp(t, scAddressOf(t, contract), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	// 1. record
	recordTx := h.build(t, h.account(t, payer.Address()), op)
	recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, true)

	if len(recorded.Results) != 1 || recorded.Results[0].AuthXDR == nil {
		t.Fatal("simulation recorded no authorization entries")
	}
	entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*recorded.Results[0].AuthXDR))
	for i, encoded := range *recorded.Results[0].AuthXDR {
		var entry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
			t.Fatalf("decoding recorded auth entry %d: %v", i, err)
		}
		entries = append(entries, entry)
	}

	validUntil, err := soroauth.ExpirationAfter(h.latestLedger(t), 1000)
	if err != nil {
		t.Fatalf("computing the expiration ledger: %v", err)
	}

	// 2. wrap the contract's entry into the delegates arm, then sign each
	// delegate by address.
	delegates := make([]soroauth.Delegate, 0, len(delegatesToAttach))
	for _, address := range delegatesToAttach {
		delegates = append(delegates, soroauth.Delegate{Address: address})
	}

	signed := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))
	for i, entry := range entries {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting recorded entry %d: %v", i, err)
		}
		if info.CredentialType == soroauth.CredentialTypeSourceAccount || info.Address != contract {
			signed = append(signed, entry)
			continue
		}

		wrapped, err := soroauth.WithDelegates(entry, validUntil, delegates, nil)
		if err != nil {
			t.Fatalf("WithDelegates on entry %d: %v", i, err)
		}

		current := wrapped
		for _, signer := range signers {
			current, err = soroauth.AuthorizeEntry(context.Background(), current,
				soroauth.NewEd25519Signer(signer), validUntil, h.passphrase,
				soroauth.ForAddress(signer.Address()))
			if err != nil {
				t.Fatalf("signing delegate %s: %v", signer.Address(), err)
			}
		}
		signed = append(signed, current)
	}

	for i, entry := range signed {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting signed entry %d: %v", i, err)
		}
		t.Logf("entry %d: %s address=%s top_signed=%v delegates=%d",
			i, info.CredentialType, info.Address, info.TopLevelSigned, len(info.Delegates))
		for _, node := range info.Delegates {
			t.Logf("           delegate %s signed=%v", node.Address, node.Signed)
		}
	}

	op.Auth = signed

	// 3. enforce, unless the point of the run is an on-chain rejection.
	sim := recorded
	headroom := uint32(1)
	if expectFailure {
		// The recording pass never ran __check_auth, so its instruction count
		// is too low to reach the rejection this scenario is about. Give the
		// submission enough budget to get there and be refused on its merits.
		headroom = 6
	} else {
		enforceTx := h.build(t, h.account(t, payer.Address()), op)
		sim = h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)
	}

	finalTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, sim, headroom)
	finalTx, err = finalTx.Sign(h.passphrase, payer)
	if err != nil {
		t.Fatalf("signing the envelope as the payer: %v", err)
	}

	return h.send(t, finalTx)
}

// TestScenarioD proves the delegated-signer arm is accepted by a live host: a
// contract account holding XLM transfers it, authorized only by two G-account
// delegates that soroauth signed.
func TestScenarioD(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	d2 := h.newAccount(t, "delegate D2")
	to := h.newAccount(t, "recipient B")

	deployed := h.deployModularAccount(t, payer, []string{d1.Address(), d2.Address()})
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	result := delegatesFlow(t, h, payer, deployed.ContractAddress, to,
		[]string{d1.Address(), d2.Address()},
		[]*keypair.Full{d1, d2},
		false)

	t.Logf("contract:  %s", deployed.ContractAddress)
	t.Logf("deploy tx: %s", deployed.CreateTxHash)
	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("ledger:    %d", result.Ledger)
	t.Logf("arm:       %s", result.Arm)
	t.Logf("link:      %s%s", explorerBaseURL, result.Hash)

	record(scenarioResult{
		ID:        "D",
		Name:      "CAP-71 delegated signers accepted live",
		Proves:    "A SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES entry, with a Void top-level signature and two G-account delegates signed by soroauth, is accepted by the host.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: []string{
			"modular-account contract: " + deployed.ContractAddress,
			"wasm upload tx: " + deployed.UploadTxHash,
			"contract deploy tx: " + deployed.CreateTxHash,
			"wasm hash: " + deployed.WasmHash,
			"Registered signers: " + d1.Address() + ", " + d2.Address(),
			"The account itself never signs: its top-level signature is ScvVoid, which CAP-71-01 permits when delegates carry the authentication.",
		},
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario D failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates" {
		t.Errorf("submitted envelope carried arm %q, want the delegates arm", result.Arm)
	}
}

// TestScenarioE proves the host rejects what it should: the same flow as D, but
// with a delegate the account has not registered. The contract's __check_auth
// returns UnknownDelegate, and this test reports the raw error verbatim.
func TestScenarioE(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	d2 := h.newAccount(t, "delegate D2")
	d3 := h.newAccount(t, "stranger D3")
	to := h.newAccount(t, "recipient B")

	// D3 is deliberately left out of the registered set.
	deployed := h.deployModularAccount(t, payer, []string{d1.Address(), d2.Address()})
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	result := delegatesFlow(t, h, payer, deployed.ContractAddress, to,
		[]string{d3.Address()},
		[]*keypair.Full{d3},
		true)

	t.Logf("contract:  %s", deployed.ContractAddress)
	t.Logf("deploy tx: %s", deployed.CreateTxHash)
	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("status:    %s", result.Status)
	t.Logf("arm:       %s", result.Arm)
	t.Logf("RAW ERROR:\n%s", result.RawError)

	record(scenarioResult{
		ID:        "E",
		Name:      "the host rejects an unregistered delegate",
		Proves:    "A delegates entry naming an address the account has not registered is refused by the contract's __check_auth with its UnknownDelegate error.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status != rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: []string{
			"modular-account contract: " + deployed.ContractAddress,
			"contract deploy tx: " + deployed.CreateTxHash,
			"Registered signers: " + d1.Address() + ", " + d2.Address(),
			"Attached delegate (not registered): " + d3.Address(),
			"AccountError::UnknownDelegate is contract error #1 in e2e/contracts/modular-account/src/lib.rs.",
		},
	})

	if result.Status == rpc.TransactionStatusSuccess {
		t.Fatal("the host accepted an unregistered delegate; scenario E proves nothing if this succeeds")
	}
	if result.RawError == "" {
		t.Error("no raw error was captured, so there is nothing to report")
	}

	// The transaction must have been refused by the account contract with
	// UnknownDelegate (#1), not for some unrelated reason such as running out
	// of instructions before __check_auth was ever reached.
	const unknownDelegate = 1
	codes := contractErrorCodes(t, result.Diagnostics)
	found := false
	for _, code := range codes {
		if code == unknownDelegate {
			found = true
		}
	}
	if !found {
		t.Errorf("the host reported contract error codes %v, want %d (AccountError::UnknownDelegate); "+
			"the transaction failed, but not for the reason this scenario is about", codes, unknownDelegate)
	} else {
		t.Logf("contract error code %d (AccountError::UnknownDelegate) confirmed in the host diagnostics", unknownDelegate)
	}
}
