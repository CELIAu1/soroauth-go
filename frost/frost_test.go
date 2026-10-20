// Package frost provides a FROST (Flexible Round-Optimized Schnorr Threshold)
// threshold signer implementation for Ed25519.
package frost

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/signertest"
)

func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, _ := keypair.FromRawSeed([32]byte{})
	_ = label
	return kp
}

func testAddress(t *testing.T, label string) string {
	t.Helper()
	kp := testKeypair(t, label)
	return kp.Address()
}

func testPreimagePayload(t *testing.T, entry xdr.SorobanAuthorizationEntry) (xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	preimage, err := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	return preimage, payload
}

func TestTrustedDealerKeygen(t *testing.T) {
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	if len(secretShares) != 3 {
		t.Fatalf("expected 3 secret shares, got %d", len(secretShares))
	}
	if len(vk) != ed25519.PublicKeySize {
		t.Fatalf("verification key size: %d", len(vk))
	}
	if len(pkShares) != 3 {
		t.Fatalf("expected 3 public key shares, got %d", len(pkShares))
	}

	// Verify all shares are 32 bytes
	for i := range secretShares {
		if len(secretShares[i]) != ed25519.PublicKeySize {
			t.Errorf("secret share %d size: %d", i, len(secretShares[i]))
		}
		if len(pkShares[i]) != ed25519.PublicKeySize {
			t.Errorf("public key share %d size: %d", i, len(pkShares[i]))
		}
	}

	// The verification key should be valid for the group
	// (We can't reconstruct individual keys from shares in Shamir sharing)
	_ = vk
}

func TestNewFROSTCoordinator(t *testing.T) {
	_, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}
	if coord.Address() != address {
		t.Errorf("Address() = %q, want %q", coord.Address(), address)
	}
}

func TestNewFROSTCoordinatorInvalidAddress(t *testing.T) {
	_, vk, pkShares, _ := TrustedDealerKeygen(2, 3)
	_, err := NewFROSTCoordinator(vk, pkShares, 2, 3, "not-a-valid-address")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewFROSTCoordinatorThresholdTooHigh(t *testing.T) {
	_, vk, pkShares, _ := TrustedDealerKeygen(2, 3)
	_, err := NewFROSTCoordinator(vk, pkShares, 4, 3, testAddress(t, "policy-test-coord"))
	if err == nil {
		t.Error("expected error for threshold > maxSigners")
	}
}

func TestFROSTParticipant(t *testing.T) {
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	participant, err := NewFROSTParticipant(secretShares[0], pkShares[0], 1, coord)
	if err != nil {
		t.Fatalf("NewFROSTParticipant: %v", err)
	}
	if participant.ID() != 1 {
		t.Errorf("ID() = %d, want 1", participant.ID())
	}
	if !equalBytes(participant.PublicKey(), pkShares[0]) {
		t.Error("PublicKey() mismatch")
	}
}

func TestFROSTSignerRoundTrip(t *testing.T) {
	// Generate keys for 2-of-3 threshold
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	// Create participants (need at least threshold=2)
	participants := make([]*FROSTParticipant, 2)
	for i := 0; i < 2; i++ {
		participants[i], err = NewFROSTParticipant(secretShares[i], pkShares[i], uint16(i+1), coord)
		if err != nil {
			t.Fatalf("NewFROSTParticipant %d: %v", i, err)
		}
	}

	signer, err := NewFROSTSigner(coord, participants)
	if err != nil {
		t.Fatalf("NewFROSTSigner: %v", err)
	}

	// Create an entry to sign
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(address); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
					Args:         []xdr.ScVal{},
				},
			},
		},
	}

	preimage, payload := testPreimagePayload(t, entry)

	sigVal, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify the signature using the group verification key (not a reconstructed key)
	// The FROST signature is a standard Ed25519 signature for the group public key
	if err := VerifySignature(vk, payload[:], extractSignatureBytes(sigVal)); err != nil {
		t.Errorf("FROST VerifySignature failed: %v", err)
	}

	// Verify the signature is valid Ed25519 format (64 bytes)
	sigBytes := extractSignatureBytes(sigVal)
	if len(sigBytes) != ed25519.SignatureSize {
		t.Errorf("signature size: %d, want %d", len(sigBytes), ed25519.SignatureSize)
	}
}

func TestFROSTSignerInsufficientParticipants(t *testing.T) {
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	// Only 1 participant (threshold is 2)
	participant, _ := NewFROSTParticipant(secretShares[0], pkShares[0], 1, coord)
	_, err = NewFROSTSigner(coord, []*FROSTParticipant{participant})
	if err == nil {
		t.Error("expected error for insufficient participants")
	}
}

func TestFROSTSignerContextCancellation(t *testing.T) {
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	participants := make([]*FROSTParticipant, 2)
	for i := 0; i < 2; i++ {
		participants[i], _ = NewFROSTParticipant(secretShares[i], pkShares[i], uint16(i+1), coord)
	}
	signer, _ := NewFROSTSigner(coord, participants)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(address); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	preimage, payload := testPreimagePayload(t, entry)

	_, err = signer.Sign(ctx, preimage, payload)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestFROSTSignerPayloadMismatch(t *testing.T) {
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	participants := make([]*FROSTParticipant, 2)
	for i := 0; i < 2; i++ {
		participants[i], _ = NewFROSTParticipant(secretShares[i], pkShares[i], uint16(i+1), coord)
	}
	signer, _ := NewFROSTSigner(coord, participants)

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(address); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	preimage, _ := testPreimagePayload(t, entry)
	wrongPayload := [32]byte{1, 2, 3}

	_, err = signer.Sign(context.Background(), preimage, wrongPayload)
	if err == nil {
		t.Error("expected error for payload mismatch")
	}
	if !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}
}

func TestFROSTSignerConformance(t *testing.T) {
	secretShares, vk, pkShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}

	address := testAddress(t, "policy-test-coord")
	coord, err := NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	participants := make([]*FROSTParticipant, 2)
	for i := 0; i < 2; i++ {
		participants[i], _ = NewFROSTParticipant(secretShares[i], pkShares[i], uint16(i+1), coord)
	}
	signer, _ := NewFROSTSigner(coord, participants)

	// Run conformance tests
	// Note: FROST is deterministic for the same message with same nonces,
	// but participants generate fresh nonces each time.
	signertest.Run(t, signertest.Config{
		Signer:        signer,
		Deterministic: false, // FROST uses fresh nonces per round
		Verify: func(sig xdr.ScVal, payload [32]byte) error {
			return VerifySignature(vk, payload[:], extractSignatureBytes(sig))
		},
	})
}

func extractSignatureBytes(val xdr.ScVal) []byte {
	// The signature is a vector with one map {public_key, signature}
	vecPtr, ok := val.GetVec()
	if !ok || vecPtr == nil {
		return nil
	}
	vec := *vecPtr
	if len(vec) != 1 {
		return nil
	}
	m := vec[0]
	mapPtr, ok := m.GetMap()
	if !ok || mapPtr == nil {
		return nil
	}
	for _, kv := range *mapPtr {
		if kv.Key.Type == xdr.ScValTypeScvSymbol && kv.Key.Sym != nil && string(*kv.Key.Sym) == "signature" {
			if kv.Val.Type == xdr.ScValTypeScvBytes && kv.Val.Bytes != nil {
				return (*kv.Val.Bytes)[:]
			}
		}
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
