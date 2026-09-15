//go:build e2e

package e2e

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"github.com/soroauth/soroauth-go"
)

// makeMultisig turns an account into a 2-of-2: the master key keeps weight 1,
// a second signer is added at weight 1, and the medium threshold is raised to
// 2 so a transfer needs both.
func (h *harness) makeMultisig(t *testing.T, account *keypair.Full, extra *keypair.Full) {
	t.Helper()

	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        h.account(t, account.Address()),
		IncrementSequenceNum: true,
		BaseFee:              txnbuild.MinBaseFee * 100,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
		Operations: []txnbuild.Operation{
			&txnbuild.SetOptions{
				MasterWeight:    txnbuild.NewThreshold(1),
				LowThreshold:    txnbuild.NewThreshold(1),
				MediumThreshold: txnbuild.NewThreshold(2),
				HighThreshold:   txnbuild.NewThreshold(2),
				Signer:          &txnbuild.Signer{Address: extra.Address(), Weight: 1},
			},
		},
	})
	if err != nil {
		t.Fatalf("building the setOptions transaction: %v", err)
	}

	// The threshold change takes effect after this transaction, so it is
	// still signed by the master key alone.
	tx, err = tx.Sign(h.passphrase, account)
	if err != nil {
		t.Fatalf("signing the setOptions transaction: %v", err)
	}

	result := h.send(t, tx)
	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("configuring multisig failed (status %s):\n%s", result.Status, result.RawError)
	}
	t.Logf("multisig configured in ledger %d (tx %s)", result.Ledger, result.Hash)
}

// TestScenarioC proves AccountMultiSigner produces a signature vector the host
// accepts. This signer has no equivalent in the JS SDK, so the golden vectors
// cannot cover it; this is the evidence that it is correct.
func TestScenarioC(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	multisig := h.newAccount(t, "account M")
	second := h.newAccount(t, "signer M2")
	to := h.newAccount(t, "recipient B")

	h.makeMultisig(t, multisig, second)

	op := h.transferOp(t, scAddressOf(t, multisig.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	signer, err := soroauth.NewAccountMultiSigner(multisig.Address(), multisig, second)
	if err != nil {
		t.Fatalf("building the multi signer: %v", err)
	}

	result := runTransfer(t, h, payer, op, []soroauth.Signer{signer}, true, nil)

	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("arm:     %s", result.Arm)
	t.Logf("link:    %s%s", explorerBaseURL, result.Hash)

	record(scenarioResult{
		ID:     "C",
		Name:   "AccountMultiSigner accepted live",
		Proves: "A signature vector from soroauth.NewAccountMultiSigner meets a 2-of-2 medium threshold on a classic account.",
		TxHash: result.Hash,
		Ledger: result.Ledger,
		Arm:    result.Arm,
		Notes: []string{
			"Account M has its master key at weight 1 plus a second signer at weight 1, with the medium threshold raised to 2, so one signature alone is not enough.",
			"Keys are sorted strictly ascending by raw public key, which is what the host requires.",
		},
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario C failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
}

// TestScenarioCRejectsASingleSignature is the control for scenario C: with the
// medium threshold at 2, one signature must not be enough. Without this, C
// would also pass on an account whose threshold was never actually raised.
func TestScenarioCRejectsASingleSignature(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	multisig := h.newAccount(t, "account M")
	second := h.newAccount(t, "signer M2")
	to := h.newAccount(t, "recipient B")

	h.makeMultisig(t, multisig, second)

	op := h.transferOp(t, scAddressOf(t, multisig.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	// Deliberately only the master key, which carries weight 1 of the 2
	// required.
	signer, err := soroauth.NewAccountMultiSigner(multisig.Address(), multisig)
	if err != nil {
		t.Fatalf("building the single-key multi signer: %v", err)
	}

	result := runTransferExpectingFailure(t, h, payer, op, []soroauth.Signer{signer})

	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("status:    %s", result.Status)
	t.Logf("raw error: %s", result.RawError)

	if result.Status == rpc.TransactionStatusSuccess {
		t.Fatal("a single signature met a threshold of 2; the account was not actually multisig")
	}
}
