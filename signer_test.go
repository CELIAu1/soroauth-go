package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// lyingKeypair signs correctly and then corrupts the result, while leaving
// Verify genuine. It is the failure the self-verification guard exists to
// catch: a signer that hands back bytes which will not verify on-chain.
type lyingKeypair struct {
	real *keypair.Full
}

func (l lyingKeypair) Address() string { return l.real.Address() }

func (l lyingKeypair) Sign(input []byte) ([]byte, error) {
	signature, err := l.real.Sign(input)
	if err != nil {
		return nil, err
	}
	signature[0] ^= 0xff
	return signature, nil
}

func (l lyingKeypair) Verify(input, signature []byte) error {
	return l.real.Verify(input, signature)
}

// accountSignaturePart is one decoded {public_key, signature} map.
type accountSignaturePart struct {
	publicKey []byte
	signature []byte
}

// decodeAccountSignature asserts the built-in account signature shape and
// returns its parts. It checks the structure the host will decode rather than
// trusting the constructor that built it.
func decodeAccountSignature(t *testing.T, value xdr.ScVal) []accountSignaturePart {
	t.Helper()

	if value.Type != xdr.ScValTypeScvVec {
		t.Fatalf("signature is %v, want a vector", value.Type)
	}
	if value.Vec == nil || *value.Vec == nil {
		t.Fatal("signature vector is nil")
	}

	parts := make([]accountSignaturePart, 0, len(**value.Vec))
	for i, element := range **value.Vec {
		if element.Type != xdr.ScValTypeScvMap {
			t.Fatalf("element %d is %v, want a map", i, element.Type)
		}
		if element.Map == nil || *element.Map == nil {
			t.Fatalf("element %d has a nil map", i)
		}
		entries := **element.Map
		if len(entries) != 2 {
			t.Fatalf("element %d has %d map entries, want 2", i, len(entries))
		}

		var part accountSignaturePart
		wantKeys := []string{"public_key", "signature"}
		for j, entry := range entries {
			if entry.Key.Type != xdr.ScValTypeScvSymbol || entry.Key.Sym == nil {
				t.Fatalf("element %d key %d is %v, want a symbol", i, j, entry.Key.Type)
			}
			// Map entries must be in key order; the host reads them as a
			// struct, and an ScMap is required to be sorted.
			if got := string(*entry.Key.Sym); got != wantKeys[j] {
				t.Fatalf("element %d key %d is %q, want %q", i, j, got, wantKeys[j])
			}
			if entry.Val.Type != xdr.ScValTypeScvBytes || entry.Val.Bytes == nil {
				t.Fatalf("element %d value %d is %v, want bytes", i, j, entry.Val.Type)
			}
			if j == 0 {
				part.publicKey = []byte(*entry.Val.Bytes)
			} else {
				part.signature = []byte(*entry.Val.Bytes)
			}
		}

		if len(part.publicKey) != ed25519.PublicKeySize {
			t.Fatalf("element %d public key is %d bytes, want %d", i, len(part.publicKey), ed25519.PublicKeySize)
		}
		if len(part.signature) != ed25519.SignatureSize {
			t.Fatalf("element %d signature is %d bytes, want %d", i, len(part.signature), ed25519.SignatureSize)
		}
		parts = append(parts, part)
	}
	return parts
}

func testPayload(label string) [32]byte {
	var payload [32]byte
	copy(payload[:], label)
	return payload
}

func TestEd25519SignerProducesTheAccountSignatureShape(t *testing.T) {
	kp := testKeypair(t, "soroauth-signer-ed25519")
	signer := NewEd25519Signer(kp)

	if got := signer.Address(); got != kp.Address() {
		t.Errorf("Address is %q, want %q", got, kp.Address())
	}

	payload := testPayload("soroauth-signer-payload")
	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	// The value goes into a credential node, so it must be legal XDR.
	if _, err := value.MarshalBinary(); err != nil {
		t.Fatalf("signature does not marshal: %v", err)
	}

	parts := decodeAccountSignature(t, value)
	if len(parts) != 1 {
		t.Fatalf("got %d signatures, want 1", len(parts))
	}

	wantKey, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("decoding the test public key: %v", err)
	}
	if !bytes.Equal(parts[0].publicKey, wantKey) {
		t.Errorf("public key\n want %x\n  got %x", wantKey, parts[0].publicKey)
	}

	// The signature must actually verify against the payload that was signed.
	if err := kp.Verify(payload[:], parts[0].signature); err != nil {
		t.Errorf("the returned signature does not verify against the payload: %v", err)
	}
}

func TestEd25519SignerRejectsItsOwnBadSignature(t *testing.T) {
	kp := testKeypair(t, "soroauth-signer-ed25519")
	signer := &ed25519Signer{kp: lyingKeypair{real: kp}}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("soroauth-signer-payload"))
	if err == nil {
		t.Fatalf("Sign accepted a corrupted signature, returning %+v", got)
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %q does not match ErrSignatureMismatch", err)
	}
	if got != (xdr.ScVal{}) {
		t.Error("Sign returned a value alongside an error")
	}
}

func TestEd25519SignerWithoutAKeypair(t *testing.T) {
	signer := NewEd25519Signer(nil)

	if got := signer.Address(); got != "" {
		t.Errorf("Address is %q, want an empty string", got)
	}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatalf("Sign succeeded without a keypair, returning %+v", got)
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
}

func TestSignersHonourContextCancellation(t *testing.T) {
	kp := testKeypair(t, "soroauth-signer-ed25519")
	multi, err := NewAccountMultiSigner(kp.Address(), kp)
	if err != nil {
		t.Fatalf("building the multi signer: %v", err)
	}

	signers := map[string]Signer{
		"ed25519":  NewEd25519Signer(kp),
		"multisig": multi,
		"func": SignerFunc(kp.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			t.Error("the callback ran despite a cancelled context")
			return xdr.ScVal{}, nil
		}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for name, signer := range signers {
		t.Run(name, func(t *testing.T) {
			if _, err := signer.Sign(ctx, xdr.HashIdPreimage{}, testPayload("x")); !errors.Is(err, context.Canceled) {
				t.Errorf("error %v does not match context.Canceled", err)
			}
		})
	}
}

func TestAccountMultiSignerOrdersKeysAscending(t *testing.T) {
	account := testKeypair(t, "soroauth-multisig-account")
	// Deliberately unsorted input, and an account whose own key is not among
	// the signers, which a Stellar account is free to do.
	kps := []*keypair.Full{
		testKeypair(t, "soroauth-multisig-key-3"),
		testKeypair(t, "soroauth-multisig-key-1"),
		testKeypair(t, "soroauth-multisig-key-2"),
	}

	signer, err := NewAccountMultiSigner(account.Address(), kps...)
	if err != nil {
		t.Fatalf("NewAccountMultiSigner returned an unexpected error: %v", err)
	}
	if got := signer.Address(); got != account.Address() {
		t.Errorf("Address is %q, want the account %q", got, account.Address())
	}

	payload := testPayload("soroauth-multisig-payload")
	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}
	if _, err := value.MarshalBinary(); err != nil {
		t.Fatalf("signature does not marshal: %v", err)
	}

	parts := decodeAccountSignature(t, value)
	if len(parts) != len(kps) {
		t.Fatalf("got %d signatures, want %d", len(parts), len(kps))
	}

	for i := 1; i < len(parts); i++ {
		if bytes.Compare(parts[i-1].publicKey, parts[i].publicKey) >= 0 {
			t.Errorf("public keys are not strictly ascending at %d:\n %x\n %x",
				i, parts[i-1].publicKey, parts[i].publicKey)
		}
	}

	// Every key must have signed, and each signature must verify.
	byKey := map[string]*keypair.Full{}
	for _, kp := range kps {
		raw, err := rawEd25519Key(kp.Address())
		if err != nil {
			t.Fatalf("decoding a test public key: %v", err)
		}
		byKey[string(raw)] = kp
	}
	for i, part := range parts {
		kp, ok := byKey[string(part.publicKey)]
		if !ok {
			t.Fatalf("signature %d is from an unexpected key %x", i, part.publicKey)
		}
		if err := kp.Verify(payload[:], part.signature); err != nil {
			t.Errorf("signature %d does not verify: %v", i, err)
		}
		delete(byKey, string(part.publicKey))
	}
	if len(byKey) != 0 {
		t.Errorf("%d keys did not sign", len(byKey))
	}
}

func TestAccountMultiSignerRejects(t *testing.T) {
	account := testKeypair(t, "soroauth-multisig-account").Address()
	kp := testKeypair(t, "soroauth-multisig-key-1")

	tooMany := make([]*keypair.Full, 0, maxAccountSignatures+1)
	for i := 0; i <= maxAccountSignatures; i++ {
		tooMany = append(tooMany, testKeypair(t, fmt.Sprintf("soroauth-multisig-bulk-%d", i)))
	}

	tests := []struct {
		name    string
		account string
		kps     []*keypair.Full
		wantErr error
		wantMsg string
	}{
		{
			name:    "no keys",
			account: account,
			kps:     nil,
			wantErr: ErrMissingSigner,
		},
		{
			name:    "a nil key",
			account: account,
			kps:     []*keypair.Full{kp, nil},
			wantErr: ErrMissingSigner,
			wantMsg: "key 1 is nil",
		},
		{
			name:    "more keys than the host accepts",
			account: account,
			kps:     tooMany,
			wantErr: ErrTooManySignatures,
			wantMsg: "at most 20",
		},
		{
			name:    "duplicate key",
			account: account,
			kps:     []*keypair.Full{kp, testKeypair(t, "soroauth-multisig-key-2"), kp},
			wantMsg: "duplicate signing key",
		},
		{
			name:    "contract address as the account",
			account: testContractAddress(t, "soroauth-multisig-contract"),
			kps:     []*keypair.Full{kp},
			wantMsg: "is not an account (G…) address",
		},
		{
			name:    "malformed account",
			account: "not-an-address",
			kps:     []*keypair.Full{kp},
			wantMsg: "is not an account (G…) address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAccountMultiSigner(tt.account, tt.kps...)
			if err == nil {
				t.Fatalf("NewAccountMultiSigner succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected sentinel %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if got != nil {
				t.Error("NewAccountMultiSigner returned a signer alongside an error")
			}
		})
	}
}

func TestAccountMultiSignerRejectsItsOwnBadSignature(t *testing.T) {
	account := testKeypair(t, "soroauth-multisig-account").Address()
	good := testKeypair(t, "soroauth-multisig-key-1")
	liar := lyingKeypair{real: testKeypair(t, "soroauth-multisig-key-2")}

	signer, err := newAccountMultiSigner(account, good, liar)
	if err != nil {
		t.Fatalf("newAccountMultiSigner returned an unexpected error: %v", err)
	}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatalf("Sign accepted a corrupted signature, returning %+v", got)
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %q does not match ErrSignatureMismatch", err)
	}
	if !strings.Contains(err.Error(), liar.Address()) {
		t.Errorf("error %q does not name the offending key %s", err, liar.Address())
	}
}

func TestSignerFuncReturnsTheValueVerbatim(t *testing.T) {
	address := testContractAddress(t, "soroauth-signerfunc-contract")

	// A shape no built-in signer would produce, to prove nothing is wrapped
	// or rewritten on the way out.
	want := scBytes([]byte("a custom account's own signature format"))

	wantPayload := testPayload("soroauth-signerfunc-payload")
	wantPreimage := xdr.HashIdPreimage{
		Type:                 xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{Nonce: 7},
	}

	var sawPreimage xdr.HashIdPreimage
	var sawPayload [32]byte
	signer := SignerFunc(address, func(_ context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		sawPreimage, sawPayload = preimage, payload
		return want, nil
	})

	if got := signer.Address(); got != address {
		t.Errorf("Address is %q, want %q", got, address)
	}

	got, err := signer.Sign(context.Background(), wantPreimage, wantPayload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	gotBytes, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the returned value: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the expected value: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("value was not returned verbatim\n want %x\n  got %x", wantBytes, gotBytes)
	}

	// The callback must receive both the structure and the digest, so a
	// remote signer can inspect what it is approving.
	if sawPayload != wantPayload {
		t.Errorf("callback saw payload %x, want %x", sawPayload, wantPayload)
	}
	if sawPreimage.Type != wantPreimage.Type || sawPreimage.SorobanAuthorization.Nonce != 7 {
		t.Errorf("callback saw preimage %+v, want the one passed in", sawPreimage)
	}
}

func TestSignerFuncPropagatesErrors(t *testing.T) {
	sentinel := errors.New("the remote signer refused")
	signer := SignerFunc("G...", func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		return xdr.ScVal{}, sentinel
	})

	if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x")); !errors.Is(err, sentinel) {
		t.Errorf("error %v does not wrap the callback's error", err)
	}
}

func TestSignerFuncWithoutACallback(t *testing.T) {
	got, err := SignerFunc("G...", nil).Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatalf("Sign succeeded without a callback, returning %+v", got)
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
}
