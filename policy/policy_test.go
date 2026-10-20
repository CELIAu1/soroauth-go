// Package policy provides a Signer decorator that enforces caller-supplied
// rules against the decoded invocation tree before delegating to the wrapped
// signer.
package policy

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair for %q: %v", label, err)
	}
	return kp
}

func testContractID(t *testing.T, label string) xdr.ContractId {
	t.Helper()
	var cid xdr.ContractId
	hash := sha256.Sum256([]byte(label))
	copy(cid[:], hash[:])
	return cid
}

func testContractAddress(t *testing.T, label string) xdr.ScAddress {
	t.Helper()
	return xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: func() *xdr.ContractId { cid := testContractID(t, label); return &cid }(),
	}
}

func contractIDToAddressString(cid xdr.ContractId) string {
	addr := xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &cid,
	}
	s, _ := soroauth.FormatAddress(addr)
	return s
}

func testInvocation(t *testing.T, contractLabel string) xdr.SorobanAuthorizedInvocation {
	t.Helper()
	return xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: testContractAddress(t, contractLabel),
				FunctionName:    xdr.ScSymbol("transfer"),
				Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvU64, U64: func() *xdr.Uint64 { v := xdr.Uint64(100); return &v }()}},
			},
		},
	}
}

func testEntry(t *testing.T, credType xdr.SorobanCredentialsType, accountLabel string) xdr.SorobanAuthorizationEntry {
	t.Helper()
	kp := testKeypair(t, accountLabel)
	address, err := soroauth.ParseAddress(kp.Address())
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	entry := xdr.SorobanAuthorizationEntry{
		RootInvocation: testInvocation(t, "policy-test-contract"),
	}
	switch credType {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		entry.Credentials.Type = credType
		entry.Credentials.AddressV2 = &xdr.SorobanAddressCredentials{
			Address:                   address,
			Nonce:                     1,
			SignatureExpirationLedger: 1000,
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		entry.Credentials.Type = credType
		entry.Credentials.Address = &xdr.SorobanAddressCredentials{
			Address:                   address,
			Nonce:                     1,
			SignatureExpirationLedger: 1000,
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		entry.Credentials.Type = credType
	}
	return entry
}

func testPreimage(t *testing.T, entry xdr.SorobanAuthorizationEntry) (xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	// Extract the expiration from the entry's credentials
	var validUntil uint32 = 1000
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		if entry.Credentials.AddressV2 != nil {
			validUntil = uint32(entry.Credentials.AddressV2.SignatureExpirationLedger)
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if entry.Credentials.Address != nil {
			validUntil = uint32(entry.Credentials.Address.SignatureExpirationLedger)
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if entry.Credentials.AddressWithDelegates != nil {
			validUntil = uint32(entry.Credentials.AddressWithDelegates.AddressCredentials.SignatureExpirationLedger)
		}
	}
	preimage, err := soroauth.Preimage(entry, validUntil, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	return preimage, payload
}

func TestPolicySignerContractAllowlist(t *testing.T) {
	kp := testKeypair(t, "policy-test-1")
	allowedContract := testContractID(t, "policy-allowed-contract")
	allowedAddr := contractIDToAddressString(allowedContract)
	rule, err := NewContractAllowlistRule([]string{allowedAddr})
	if err != nil {
		t.Fatalf("NewContractAllowlistRule: %v", err)
	}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	// Allowed contract
	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry")
	entry.RootInvocation.Function.ContractFn.ContractAddress.ContractId = &allowedContract
	preimage, payload := testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Errorf("allowed contract refused: %v", err)
	}

	// Disallowed contract
	disallowedContract := testContractID(t, "policy-disallowed-contract")
	entry.RootInvocation.Function.ContractFn.ContractAddress.ContractId = &disallowedContract
	preimage, payload = testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("disallowed contract was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "contract_allowlist" {
		t.Errorf("expected rule 'contract_allowlist', got %q", refusal.Rule)
	}
}

func TestPolicySignerMaxAmount(t *testing.T) {
	kp := testKeypair(t, "policy-test-2")
	rule := NewMaxAmountRule(1000)

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	// Amount within limit
	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-2")
	entry.RootInvocation.Function.ContractFn.Args[0] = xdr.ScVal{
		Type: xdr.ScValTypeScvU64,
		U64:  func() *xdr.Uint64 { v := xdr.Uint64(500); return &v }(),
	}
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Errorf("amount within limit refused: %v", err)
	}

	// Amount exceeds limit
	entry.RootInvocation.Function.ContractFn.Args[0] = xdr.ScVal{
		Type: xdr.ScValTypeScvU64,
		U64:  func() *xdr.Uint64 { v := xdr.Uint64(2000); return &v }(),
	}
	preimage, payload = testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("amount exceeding limit was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "max_amount" {
		t.Errorf("expected rule 'max_amount', got %q", refusal.Rule)
	}
}

func TestPolicySignerForbiddenSACAdmin(t *testing.T) {
	kp := testKeypair(t, "policy-test-3")
	rule := &ForbiddenSACAdminRule{}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	// Normal function
	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-3")
	entry.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("transfer")
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Errorf("normal function refused: %v", err)
	}

	// Forbidden admin function
	entry.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("set_admin")
	preimage, payload = testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("forbidden SAC admin function was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "forbidden_sac_admin" {
		t.Errorf("expected rule 'forbidden_sac_admin', got %q", refusal.Rule)
	}
}

func TestPolicySignerAddressBound(t *testing.T) {
	kp := testKeypair(t, "policy-test-4")
	rule := &AddressBoundRule{}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	// V2 credentials - allowed
	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-4")
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Errorf("V2 credentials refused: %v", err)
	}

	// Legacy ADDRESS credentials - NOT rejected because the preimage doesn't
	// carry enough information to distinguish it from SOURCE_ACCOUNT.
	// This is a known limitation: AddressBoundRule only enforces for
	// ADDRESS_V2 and ADDRESS_WITH_DELEGATES credentials.
	entry = testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, "policy-test-entry-4")
	preimage, payload = testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Errorf("legacy ADDRESS credentials were refused (known limitation: not enforceable from preimage): %v", err)
	}
}

func TestPolicySignerInnerNeverInvokedOnRefusal(t *testing.T) {
	kp := testKeypair(t, "policy-test-5")
	rule := NewMaxAmountRule(100)

	invoked := false
	inner := soroauth.SignerFunc(kp.Address(), func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		invoked = true
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
	})
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-5")
	entry.RootInvocation.Function.ContractFn.Args[0] = xdr.ScVal{
		Type: xdr.ScValTypeScvU64,
		U64:  func() *xdr.Uint64 { v := xdr.Uint64(200); return &v }(),
	}
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("expected refusal")
	}
	if invoked {
		t.Error("inner signer was invoked despite policy refusal")
	}
}

func TestPolicySignerFailClosedOnDecodeFailure(t *testing.T) {
	kp := testKeypair(t, "policy-test-6")
	rule := &AddressBoundRule{}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	// Create a preimage with an unsupported type
	preimage := xdr.HashIdPreimage{Type: xdr.EnvelopeType(999)}
	payload := [32]byte{}

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("unsupported preimage type was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "decode" {
		t.Errorf("expected rule 'decode', got %q", refusal.Rule)
	}
}

func TestPolicySignerRiskCriticalFindingRefused(t *testing.T) {
	kp := testKeypair(t, "policy-test-7")
	rule := &AddressBoundRule{}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule}, WithRiskConfig(&soroauth.RiskConfig{
		CurrentLedger: 100,
	}))

	// Entry with zero expiration (critical finding)
	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-7")
	entry.Credentials.AddressV2.SignatureExpirationLedger = 0
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("entry with zero expiration was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "risk:EXPIRATION_ZERO" {
		t.Errorf("expected rule 'risk:EXPIRATION_ZERO', got %q", refusal.Rule)
	}
}

func TestPolicySignerCustomVerifier(t *testing.T) {
	kp := testKeypair(t, "policy-test-8")

	customVerifyCalled := false
	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, nil, WithCustomVerifier(func(entry xdr.SorobanAuthorizationEntry) error {
		customVerifyCalled = true
		if entry.RootInvocation.Function.ContractFn != nil {
			fn := string(entry.RootInvocation.Function.ContractFn.FunctionName)
			if fn == "forbidden" {
				return errors.New("custom: forbidden function")
			}
		}
		return nil
	}))

	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-8")
	entry.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("forbidden")
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("custom verifier refusal was allowed")
	}
	if !customVerifyCalled {
		t.Error("custom verifier was not called")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "custom" {
		t.Errorf("expected rule 'custom', got %q", refusal.Rule)
	}
}

func TestPolicySignerFunctionAllowlist(t *testing.T) {
	kp := testKeypair(t, "policy-test-9")
	rule := NewFunctionAllowlistRule([]string{"transfer", "mint"})

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	// Allowed function
	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-9")
	entry.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("transfer")
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Errorf("allowed function refused: %v", err)
	}

	// Disallowed function
	entry.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("burn")
	preimage, payload = testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("disallowed function was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "function_allowlist" {
		t.Errorf("expected rule 'function_allowlist', got %q", refusal.Rule)
	}
}

func TestPolicySignerSubInvocationsChecked(t *testing.T) {
	kp := testKeypair(t, "policy-test-10")
	allowedContract := testContractID(t, "policy-allowed-contract-2")
	allowedAddr := contractIDToAddressString(allowedContract)
	rule, err := NewContractAllowlistRule([]string{allowedAddr})
	if err != nil {
		t.Fatalf("NewContractAllowlistRule: %v", err)
	}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-10")
	// Root calls allowed contract
	entry.RootInvocation.Function.ContractFn.ContractAddress.ContractId = &allowedContract
	// But sub-invocation calls disallowed contract
	disallowedContract := testContractID(t, "policy-disallowed-contract-2")
	entry.RootInvocation.SubInvocations = []xdr.SorobanAuthorizedInvocation{
		{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &disallowedContract,
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}
	preimage, payload := testPreimage(t, entry)

	_, err = wrapped.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("disallowed sub-invocation contract was allowed")
	}
	var refusal *ErrPolicyRefusal
	if !errors.As(err, &refusal) {
		t.Errorf("expected ErrPolicyRefusal, got %T: %v", err, err)
	}
	if refusal.Rule != "contract_allowlist" {
		t.Errorf("expected rule 'contract_allowlist', got %q", refusal.Rule)
	}
}

func TestPolicySignerContextCancellation(t *testing.T) {
	kp := testKeypair(t, "policy-test-11")
	rule := &AddressBoundRule{}

	inner := soroauth.NewEd25519Signer(kp)
	wrapped := NewPolicySigner(inner, []PolicyRule{rule})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := testEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, "policy-test-entry-11")
	preimage, payload := testPreimage(t, entry)

	_, err := wrapped.Sign(ctx, preimage, payload)
	if err == nil {
		t.Error("cancelled context was allowed")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestErrPolicyRefusalUnwrap(t *testing.T) {
	err := &ErrPolicyRefusal{Rule: "test", Node: "node", Cause: errors.New("cause")}
	if !errors.Is(err, soroauth.ErrPolicyRefusal) {
		t.Error("ErrPolicyRefusal should wrap soroauth.ErrPolicyRefusal")
	}
}
