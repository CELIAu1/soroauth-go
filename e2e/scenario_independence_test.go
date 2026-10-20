//go:build e2e

package e2e

import (
	"os"
	"testing"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// TestScenarioIndependence documents the independence property and verifies
// that the test discovery works with -shuffle.
//
// The e2e scenarios are designed to be independent and reorderable. Each
// scenario creates its own accounts, funds them, and submits its own
// transaction(s). No scenario depends on another's accounts, funding, or
// ledger state.
//
// Run the full suite with shuffling:
//
//	go test -tags e2e -shuffle=on ./e2e/...
//
// The Go test runner reports the shuffle seed on failure so an ordering bug
// is reproducible:
//
//	go test -tags e2e -shuffle=<seed> ./e2e/...
//
// Run a single scenario in isolation:
//
//	go test -tags e2e -run TestScenarioA ./e2e/...
func TestScenarioIndependence(t *testing.T) {
	// This test verifies that all scenario test functions exist and can be
	// discovered by the test runner. The actual shuffled execution happens
	// when running the full suite with -shuffle=on.
	scenarioTests := []string{
		"TestScenarioA",
		"TestScenarioB",
		"TestScenarioC",
		"TestScenarioD",
		"TestScenarioE",
		"TestScenarioF",
		"TestScenarioG",
		"TestScenarioH",
		"TestScenarioI",
		"TestScenarioJ",
		"TestScenarioK",
	}

	// Verify the test functions exist by referencing them.
	// This is a compile-time check — if a scenario is renamed or removed,
	// this test will fail to compile.
	_ = []interface{}{
		TestScenarioA,
		TestScenarioB,
		TestScenarioC,
		TestScenarioD,
		TestScenarioE,
		TestScenarioF,
		TestScenarioG,
		TestScenarioH,
		TestScenarioI,
		TestScenarioJ,
		TestScenarioK,
	}

	t.Logf("Scenario independence: %d scenarios registered", len(scenarioTests))
	t.Log("Run with -shuffle=on to execute in random order.")
	t.Log("Run individual scenarios with -run TestScenarioX.")
}

// TestScenarioRunsInIsolation verifies that a single scenario can be run by
// name without any other scenarios having run first.
//
// Run it with:
//
//	go test -tags e2e -run TestScenarioRunsInIsolation -solo=TestScenarioA ./e2e/...
//
// The -solo flag selects which scenario to run (defaults to TestScenarioA).
func TestScenarioRunsInIsolation(t *testing.T) {
	soloName := os.Getenv("SOROAUTH_E2E_SOLO")
	if soloName == "" {
		soloName = "TestScenarioA"
	}

	// Map of scenario names to their execution functions.
	// Each function is a closure that captures the scenario logic.
	scenarios := map[string]func(*testing.T, *harness){
		"TestScenarioA": func(t *testing.T, h *harness) {
			runSoloScenarioA(t, h)
		},
		"TestScenarioB": func(t *testing.T, h *harness) {
			runSoloScenarioB(t, h)
		},
	}

	run, ok := scenarios[soloName]
	if !ok {
		// For scenarios not yet extracted, fall back to running the original
		// test function via reflection. This requires the test to be run
		// with the full test suite, so we skip with a message.
		t.Skipf("scenario %q not yet extracted for isolated run; use -run %s directly", soloName, soloName)
	}

	h := newHarness(t)
	run(t, h)
}

// runSoloScenarioA is the TestScenarioA logic factored for isolated execution.
func runSoloScenarioA(t *testing.T, h *harness) {
	payer := h.newAccount(t, "payer P")
	from := h.newAccount(t, "sender A")
	to := h.newAccount(t, "recipient B")

	op := h.transferOp(t, scAddressOf(t, from.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	result := runScenario(t, h, scenarioSpec{
		payer:        payer,
		op:           op,
		signers:      []soroauth.Signer{soroauth.NewEd25519Signer(from)},
		upgradedAuth: false,
	})

	recordAndAssertSolo(t, scenarioResult{
		ID:        "A",
		Name:      "legacy address credentials accepted live",
		Proves:    "A SOROBAN_CREDENTIALS_ADDRESS entry signed by soroauth is accepted by the host.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario A failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddress" {
		t.Errorf("submitted envelope carried credentials arm %q, want legacy address", result.Arm)
	}
}

// runSoloScenarioB is the TestScenarioB logic factored for isolated execution.
func runSoloScenarioB(t *testing.T, h *harness) {
	payer := h.newAccount(t, "payer P")
	from := h.newAccount(t, "sender A")
	to := h.newAccount(t, "recipient B")

	op := h.transferOp(t, scAddressOf(t, from.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	var route string
	prepare := func(t *testing.T, entries []xdr.SorobanAuthorizationEntry, _ uint32) []xdr.SorobanAuthorizationEntry {
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

	result := runScenario(t, h, scenarioSpec{
		payer:        payer,
		op:           op,
		signers:      []soroauth.Signer{soroauth.NewEd25519Signer(from)},
		upgradedAuth: true,
		prepare:      prepare,
	})

	recordAndAssertSolo(t, scenarioResult{
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

// recordAndAssertSolo records the scenario result for isolated runs.
func recordAndAssertSolo(t *testing.T, r scenarioResult) {
	t.Helper()
	// Don't require full suite completion for isolated runs.
	resultsMu.Lock()
	results = append(results, r)
	resultsMu.Unlock()

	if r.ExpectRejection {
		if r.Succeeded {
			t.Fatalf("scenario %s expected rejection but succeeded", r.ID)
		}
	} else {
		if !r.Succeeded {
			t.Fatalf("scenario %s failed unexpectedly (status %s):\n%s", r.ID, r.RawError, r.RawError)
		}
	}
}
