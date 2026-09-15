package soroauth

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// signedEntryFixture is an unsigned entry on the given arm plus the signer that
// owns its top-level address.
func signedEntryFixture(t *testing.T, armType xdr.SorobanCredentialsType) (xdr.SorobanAuthorizationEntry, Signer) {
	t.Helper()
	entry := entryForArm(t, armType, 42)
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))
	return entry, signer
}

// assertSignatureVerifies checks that the signature stored on the entry really
// signs the payload that entry now commits to. This is the property that
// decides whether the host accepts it.
func assertSignatureVerifies(t *testing.T, entry xdr.SorobanAuthorizationEntry, validUntilLedger uint32, passphrase string) {
	t.Helper()

	preimage, err := Preimage(entry, validUntilLedger, passphrase)
	if err != nil {
		t.Fatalf("rebuilding the preimage: %v", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("rehashing the preimage: %v", err)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading the entry's credentials: %v", err)
	}
	parts := decodeAccountSignature(t, credentials.Signature)
	if len(parts) != 1 {
		t.Fatalf("got %d signatures, want 1", len(parts))
	}

	address, err := FormatAddress(credentials.Address)
	if err != nil {
		t.Fatalf("formatting the credential address: %v", err)
	}
	wantKey, err := rawEd25519Key(address)
	if err != nil {
		t.Fatalf("decoding the credential address: %v", err)
	}
	if !bytes.Equal(parts[0].publicKey, wantKey) {
		t.Errorf("the signature is from %x, but the node names %x", parts[0].publicKey, wantKey)
	}

	kp := testKeypair(t, "soroauth-preimage-signer")
	if err := kp.Verify(payload[:], parts[0].signature); err != nil {
		t.Errorf("the stored signature does not verify against the entry's own payload: %v", err)
	}
}

func TestAuthorizeEntrySignsAddressArms(t *testing.T) {
	tests := []struct {
		name    string
		armType xdr.SorobanCredentialsType
	}{
		{name: "legacy address", armType: xdr.SorobanCredentialsTypeSorobanCredentialsAddress},
		{name: "address v2", armType: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, signer := signedEntryFixture(t, tt.armType)

			signed, err := AuthorizeEntry(context.Background(), entry, signer,
				testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
			}

			if signed.Credentials.Type != tt.armType {
				t.Errorf("credentials arm changed to %v, want %v", signed.Credentials.Type, tt.armType)
			}

			credentials, err := addressCredentials(signed.Credentials)
			if err != nil {
				t.Fatalf("reading the signed credentials: %v", err)
			}
			if got := credentials.SignatureExpirationLedger; got != xdr.Uint32(testValidUntilLedger) {
				t.Errorf("expiration is %d, want %d", got, testValidUntilLedger)
			}
			if !isSigned(credentials.Signature) {
				t.Fatal("the credential node was not signed")
			}
			if _, err := signed.MarshalBinary(); err != nil {
				t.Fatalf("the signed entry does not marshal: %v", err)
			}

			assertSignatureVerifies(t, signed, testValidUntilLedger, network.TestNetworkPassphrase)
		})
	}
}

// TestAuthorizeEntryDoesNotMutateItsInput is the §4 requirement: the caller's
// entry must be byte-identical afterwards.
func TestAuthorizeEntryDoesNotMutateItsInput(t *testing.T) {
	arms := []xdr.SorobanCredentialsType{
		xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
	}

	for _, armType := range arms {
		t.Run(armType.String(), func(t *testing.T) {
			entry, signer := signedEntryFixture(t, armType)
			before, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling the entry: %v", err)
			}

			signed, err := AuthorizeEntry(context.Background(), entry, signer,
				testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
			}

			after, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("re-marshalling the entry: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("AuthorizeEntry mutated its input\n before %x\n  after %x", before, after)
			}

			// Writing through the result must not reach the input either.
			signed.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
			rechecked, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("re-marshalling the entry: %v", err)
			}
			if !bytes.Equal(before, rechecked) {
				t.Error("the returned entry still shares memory with the input")
			}
		})
	}
}

func TestAuthorizeEntryPassesSourceAccountThrough(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount)
	before, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the entry: %v", err)
	}

	// Deliberately an expiration of zero and a signer for a different
	// address: neither is consulted for this arm.
	signed, err := AuthorizeEntry(context.Background(), entry, signer, 0, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
	}

	after, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the result: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the source-account entry was changed\n before %x\n  after %x", before, after)
	}
}

// TestAuthorizeEntryOnlyWritesToTheTargetNode covers soroauth's deliberate
// difference from the JS reference: a key that does not own the node never
// writes to it.
func TestAuthorizeEntryOnlyWritesToTheTargetNode(t *testing.T) {
	entry, _ := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	stranger := NewEd25519Signer(testKeypair(t, "soroauth-authorize-stranger"))

	got, err := AuthorizeEntry(context.Background(), entry, stranger,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatalf("AuthorizeEntry signed with a key that owns no node, returning %+v", got)
	}
	if !errors.Is(err, ErrNoMatchingCredentialNode) {
		t.Errorf("error %q does not match ErrNoMatchingCredentialNode", err)
	}
}

func TestAuthorizeEntryForAddress(t *testing.T) {
	entry, _ := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	nodeOwner := testKeypair(t, "soroauth-preimage-signer")

	t.Run("names the node a foreign signer writes to", func(t *testing.T) {
		// A signer whose own address is different, pointed at the node by
		// ForAddress. The signature bytes are still the node owner's here
		// only because the test reuses that keypair; what matters is that
		// the target, not the signer's address, chose the node.
		signer := SignerFunc(
			testKeypair(t, "soroauth-authorize-stranger").Address(),
			func(_ context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
				signature, err := nodeOwner.Sign(payload[:])
				if err != nil {
					return xdr.ScVal{}, err
				}
				raw, err := rawEd25519Key(nodeOwner.Address())
				if err != nil {
					return xdr.ScVal{}, err
				}
				return scVec(accountSignature(raw, signature)), nil
			})

		signed, err := AuthorizeEntry(context.Background(), entry, signer,
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(nodeOwner.Address()))
		if err != nil {
			t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
		}
		assertSignatureVerifies(t, signed, testValidUntilLedger, network.TestNetworkPassphrase)
	})

	t.Run("an address that is not in the entry is an error", func(t *testing.T) {
		signer := NewEd25519Signer(nodeOwner)
		absent := testKeypair(t, "soroauth-authorize-stranger").Address()

		got, err := AuthorizeEntry(context.Background(), entry, signer,
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(absent))
		if err == nil {
			t.Fatalf("AuthorizeEntry succeeded for an absent address, returning %+v", got)
		}
		if !errors.Is(err, ErrNoMatchingCredentialNode) {
			t.Errorf("error %q does not match ErrNoMatchingCredentialNode", err)
		}
		if !strings.Contains(err.Error(), absent) {
			t.Errorf("error %q does not name the address that was looked for", err)
		}
	})
}

func TestAuthorizeEntryResignGuard(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)

	signed, err := AuthorizeEntry(context.Background(), entry, signer,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("the first AuthorizeEntry returned an unexpected error: %v", err)
	}

	t.Run("refuses to overwrite by default", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), signed, signer,
			testValidUntilLedger+1, network.TestNetworkPassphrase)
		if err == nil {
			t.Fatalf("AuthorizeEntry overwrote a signature, returning %+v", got)
		}
		if !errors.Is(err, ErrAlreadySigned) {
			t.Errorf("error %q does not match ErrAlreadySigned", err)
		}
	})

	t.Run("allows it with AllowResign", func(t *testing.T) {
		resigned, err := AuthorizeEntry(context.Background(), signed, signer,
			testValidUntilLedger+1, network.TestNetworkPassphrase, AllowResign())
		if err != nil {
			t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
		}
		assertSignatureVerifies(t, resigned, testValidUntilLedger+1, network.TestNetworkPassphrase)

		// The re-signed entry must really differ; a no-op would pass the
		// check above.
		before, err := signed.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		after, err := resigned.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		if bytes.Equal(before, after) {
			t.Error("re-signing produced an identical entry")
		}
	})

	t.Run("an empty vector placeholder is not a signature", func(t *testing.T) {
		// Simulation returns an empty vector as the to-be-filled value, so
		// it must not trip the guard.
		fresh, freshSigner := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
		fresh.Credentials.AddressV2.Signature = scVec()
		if _, err := AuthorizeEntry(context.Background(), fresh, freshSigner,
			testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			t.Errorf("an empty-vector placeholder was treated as a signature: %v", err)
		}
	})

	t.Run("a void placeholder is not a signature", func(t *testing.T) {
		fresh, freshSigner := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
		fresh.Credentials.AddressV2.Signature = xdr.ScVal{Type: xdr.ScValTypeScvVoid}
		if _, err := AuthorizeEntry(context.Background(), fresh, freshSigner,
			testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			t.Errorf("a void placeholder was treated as a signature: %v", err)
		}
	})
}

func TestAuthorizeEntryRejects(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signerError := errors.New("the hardware signer refused")

	tests := []struct {
		name       string
		entry      func(t *testing.T) xdr.SorobanAuthorizationEntry
		signer     Signer
		ledger     uint32
		passphrase string
		wantErr    error
	}{
		{
			name:       "zero expiration",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     signer,
			ledger:     0,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrInvalidExpiration,
		},
		{
			name: "unknown credentials arm",
			entry: func(*testing.T) xdr.SorobanAuthorizationEntry {
				e := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
				e.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)}
				return e
			},
			signer:     signer,
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrUnsupportedCredentials,
		},
		{
			name:       "nil signer",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     nil,
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrMissingSigner,
		},
		{
			name:       "signer with no address and no ForAddress",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     NewEd25519Signer(nil),
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrMissingSigner,
		},
		{
			name:  "the signer fails",
			entry: func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer: SignerFunc(testKeypair(t, "soroauth-preimage-signer").Address(),
				func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
					return xdr.ScVal{}, signerError
				}),
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    signerError,
		},
		{
			name:       "empty network passphrase",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     signer,
			ledger:     testValidUntilLedger,
			passphrase: "",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthorizeEntry(context.Background(), tt.entry(t), tt.signer, tt.ledger, tt.passphrase)
			if err == nil {
				t.Fatalf("AuthorizeEntry succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected error %q", err, tt.wantErr)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: ") {
				t.Errorf("error %q is not wrapped with the soroauth prefix", err)
			}
			if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
				t.Error("AuthorizeEntry returned an entry alongside an error")
			}
		})
	}
}
