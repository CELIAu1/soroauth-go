package soroauth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// entryForSigner builds an address entry owned by the given test label.
func entryForSigner(t *testing.T, label string, armType xdr.SorobanCredentialsType, nonce int64) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, armType, nonce)
	address, err := ParseAddress(testKeypair(t, label).Address())
	if err != nil {
		t.Fatalf("parsing %q: %v", label, err)
	}
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading credentials: %v", err)
	}
	credentials.Address = address
	return entry
}

func TestAuthorizeAllSignsEveryEntry(t *testing.T) {
	first := "soroauth-batch-1"
	second := "soroauth-batch-2"

	entries := []xdr.SorobanAuthorizationEntry{
		entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1),
		entryForSigner(t, first, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 2),
		entryForSigner(t, second, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 3),
	}

	sourceBefore, err := entries[0].MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	signed, err := AuthorizeAll(context.Background(), entries, []Signer{
		NewEd25519Signer(testKeypair(t, first)),
		NewEd25519Signer(testKeypair(t, second)),
	}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}
	if len(signed) != len(entries) {
		t.Fatalf("got %d entries back, want %d", len(signed), len(entries))
	}

	// The source-account entry is returned untouched.
	sourceAfter, err := signed[0].MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(sourceBefore, sourceAfter) {
		t.Error("the source-account entry was changed")
	}

	for i, label := range []string{first, second} {
		entry := signed[i+1]
		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			t.Fatalf("reading credentials: %v", err)
		}
		if !isSigned(credentials.Signature) {
			t.Fatalf("entry %d was returned unsigned", i+1)
		}
		if credentials.SignatureExpirationLedger != xdr.Uint32(testValidUntilLedger) {
			t.Errorf("entry %d expiration is %d, want %d",
				i+1, credentials.SignatureExpirationLedger, testValidUntilLedger)
		}

		preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			t.Fatalf("rebuilding the preimage: %v", err)
		}
		payload, err := Payload(preimage)
		if err != nil {
			t.Fatalf("rehashing: %v", err)
		}
		parts := decodeAccountSignature(t, credentials.Signature)
		if err := testKeypair(t, label).Verify(payload[:], parts[0].signature); err != nil {
			t.Errorf("entry %d signature does not verify: %v", i+1, err)
		}
	}
}

// TestAuthorizeAllNeverSkipsAnEntry is the rule that matters most here: a
// missing signer must fail the batch, not silently leave an entry unsigned.
func TestAuthorizeAllNeverSkipsAnEntry(t *testing.T) {
	present := "soroauth-batch-1"
	absent := "soroauth-batch-2"

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, present, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, absent, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	got, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(testKeypair(t, present))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatalf("AuthorizeAll skipped an entry instead of failing, returning %d entries", len(got))
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
	if !strings.Contains(err.Error(), testKeypair(t, absent).Address()) {
		t.Errorf("error %q does not name the address with no signer", err)
	}
	if got != nil {
		t.Errorf("AuthorizeAll returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeAllIsAllOrNothing: even when earlier entries signed fine, a
// later failure must leave nothing behind.
func TestAuthorizeAllIsAllOrNothing(t *testing.T) {
	good := "soroauth-batch-1"
	bad := "soroauth-batch-2"
	signerError := errors.New("the hardware signer refused")

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, good, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, bad, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	got, err := AuthorizeAll(context.Background(), entries, []Signer{
		NewEd25519Signer(testKeypair(t, good)),
		SignerFunc(testKeypair(t, bad).Address(),
			func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
				return xdr.ScVal{}, signerError
			}),
	}, testValidUntilLedger, network.TestNetworkPassphrase)

	if err == nil {
		t.Fatal("AuthorizeAll succeeded despite a failing signer")
	}
	if !errors.Is(err, signerError) {
		t.Errorf("error %q does not wrap the signer's error", err)
	}
	if got != nil {
		t.Errorf("AuthorizeAll returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeAllFillsDelegateTrees applies several signers to one delegates
// entry, each targeted by address.
func TestAuthorizeAllFillsDelegateTrees(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1")
	d2 := testKeypair(t, "soroauth-delegate-2")
	nested := testKeypair(t, "soroauth-delegate-nested-1")

	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: d1.Address(), Nested: []Delegate{{Address: nested.Address()}}},
		{Address: d2.Address()},
	}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	signed, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(d1), NewEd25519Signer(d2), NewEd25519Signer(nested)},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}

	info, err := Inspect(signed[0])
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	// The account itself never signed: CAP-71-01 allows a Void top-level
	// signature when the delegates carry the authentication.
	if info.TopLevelSigned {
		t.Error("the top-level node was signed even though no signer owns that address")
	}

	var signedNodes int
	var walk func(nodes []NodeInfo)
	walk = func(nodes []NodeInfo) {
		for _, node := range nodes {
			if node.Signed {
				signedNodes++
			}
			walk(node.Nested)
		}
	}
	walk(info.Delegates)
	if signedNodes != 3 {
		t.Errorf("%d delegate nodes are signed, want 3", signedNodes)
	}
}

// TestAuthorizeAllAcceptsDelegatesWithoutATopLevelSigner pins down the
// ambiguity resolved in AuthorizeAll's doc comment: one matching signer
// anywhere in the tree is enough, because requiring the account's own
// signature would break the delegates-only pattern CAP-71-01 allows.
func TestAuthorizeAllAcceptsDelegatesWithoutATopLevelSigner(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	delegate := testKeypair(t, "soroauth-delegate-1")

	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: delegate.Address()}}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	signed, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(delegate)},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll rejected a delegates-only entry: %v", err)
	}

	info, err := Inspect(signed[0])
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	if info.TopLevelSigned {
		t.Error("the top-level node was signed")
	}
	if len(info.Delegates) != 1 || !info.Delegates[0].Signed {
		t.Error("the delegate was not signed")
	}
}

// And the other half: a delegates entry nobody can sign must still fail.
func TestAuthorizeAllRejectsDelegatesWithNoMatchingSigner(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(testKeypair(t, "soroauth-authorize-stranger"))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("AuthorizeAll accepted an entry no signer can sign")
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
	if got != nil {
		t.Error("AuthorizeAll returned entries alongside an error")
	}
}

func TestAuthorizeAllDoesNotMutateItsInput(t *testing.T) {
	label := "soroauth-batch-1"
	entries := []xdr.SorobanAuthorizationEntry{
		entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	before := make([][]byte, len(entries))
	for i, entry := range entries {
		encoded, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		before[i] = encoded
	}

	signed, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(testKeypair(t, label))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}

	for i, entry := range entries {
		after, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshalling: %v", err)
		}
		if !bytes.Equal(before[i], after) {
			t.Errorf("entry %d was mutated\n before %x\n  after %x", i, before[i], after)
		}
	}

	// Writing through a result must not reach the input, including the
	// source-account entry that was only copied.
	for i := range signed {
		signed[i].RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	}
	for i, entry := range entries {
		after, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshalling: %v", err)
		}
		if !bytes.Equal(before[i], after) {
			t.Errorf("result %d still shares memory with the input", i)
		}
	}
}

func TestAuthorizeAllEmptyBatch(t *testing.T) {
	got, err := AuthorizeAll(context.Background(), nil, nil,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error for an empty batch: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries for an empty batch", len(got))
	}
}
