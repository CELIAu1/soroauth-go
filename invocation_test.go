package soroauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestAuthorizeInvocationDefaultsToV2(t *testing.T) {
	kp := testKeypair(t, "soroauth-invocation-signer")

	tests := []struct {
		name    string
		legacy  bool
		wantArm xdr.SorobanCredentialsType
	}{
		{
			// The zero value of Legacy is false, so the default arm is V2.
			name:    "default is address v2",
			legacy:  false,
			wantArm: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		},
		{
			name:    "legacy when asked",
			legacy:  true,
			wantArm: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := AuthorizeInvocation(context.Background(), AuthorizeInvocationParams{
				Signer:            NewEd25519Signer(kp),
				Invocation:        testInvocation(t),
				ValidUntilLedger:  testValidUntilLedger,
				NetworkPassphrase: network.TestNetworkPassphrase,
				Legacy:            tt.legacy,
			})
			if err != nil {
				t.Fatalf("AuthorizeInvocation returned an unexpected error: %v", err)
			}
			if entry.Credentials.Type != tt.wantArm {
				t.Errorf("credentials arm is %v, want %v", entry.Credentials.Type, tt.wantArm)
			}

			credentials, err := addressCredentials(entry.Credentials)
			if err != nil {
				t.Fatalf("reading the credentials: %v", err)
			}
			if got := credentials.SignatureExpirationLedger; got != xdr.Uint32(testValidUntilLedger) {
				t.Errorf("expiration is %d, want %d", got, testValidUntilLedger)
			}
			address, err := FormatAddress(credentials.Address)
			if err != nil {
				t.Fatalf("formatting the address: %v", err)
			}
			if address != kp.Address() {
				t.Errorf("entry names %s, want the signer's address %s", address, kp.Address())
			}
			if !isSigned(credentials.Signature) {
				t.Error("the entry was not signed")
			}
			if _, err := entry.MarshalBinary(); err != nil {
				t.Fatalf("the entry does not marshal: %v", err)
			}

			// The stored signature must verify against the payload the entry
			// itself commits to.
			preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("rebuilding the preimage: %v", err)
			}
			payload, err := Payload(preimage)
			if err != nil {
				t.Fatalf("rehashing: %v", err)
			}
			parts := decodeAccountSignature(t, credentials.Signature)
			if len(parts) != 1 {
				t.Fatalf("got %d signatures, want 1", len(parts))
			}
			if err := kp.Verify(payload[:], parts[0].signature); err != nil {
				t.Errorf("the stored signature does not verify against the entry's own payload: %v", err)
			}

			// The invocation must be carried through unchanged.
			want, err := testInvocation(t).MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			got, err := entry.RootInvocation.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if string(want) != string(got) {
				t.Errorf("invocation changed\n want %x\n  got %x", want, got)
			}
		})
	}
}

// TestAuthorizeInvocationNoncesAreUnpredictable checks the one property the
// nonce must have. A repeated nonce is a signature the host will reject as
// already consumed; a predictable one is worse.
func TestAuthorizeInvocationNoncesAreUnpredictable(t *testing.T) {
	kp := testKeypair(t, "soroauth-invocation-signer")

	const runs = 64
	seen := make(map[xdr.Int64]bool, runs)
	negatives := 0

	for i := 0; i < runs; i++ {
		entry, err := AuthorizeInvocation(context.Background(), AuthorizeInvocationParams{
			Signer:            NewEd25519Signer(kp),
			Invocation:        testInvocation(t),
			ValidUntilLedger:  testValidUntilLedger,
			NetworkPassphrase: network.TestNetworkPassphrase,
		})
		if err != nil {
			t.Fatalf("run %d returned an unexpected error: %v", i, err)
		}
		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			t.Fatalf("reading the credentials: %v", err)
		}
		if seen[credentials.Nonce] {
			t.Fatalf("nonce %d repeated within %d runs", credentials.Nonce, runs)
		}
		seen[credentials.Nonce] = true
		if credentials.Nonce < 0 {
			negatives++
		}
	}

	// The nonce is a signed int64 read from 8 random bytes, so about half
	// should be negative. All-positive would mean the sign bit is being
	// masked off somewhere, halving the space.
	if negatives == 0 || negatives == runs {
		t.Errorf("%d of %d nonces were negative; the value is meant to span the full int64 range",
			negatives, runs)
	}
}

func TestAuthorizeInvocationRejects(t *testing.T) {
	kp := testKeypair(t, "soroauth-invocation-signer")
	signerError := errors.New("the signer refused")

	tests := []struct {
		name    string
		params  AuthorizeInvocationParams
		wantErr error
		wantMsg string
	}{
		{
			name: "no signer",
			params: AuthorizeInvocationParams{
				Invocation:        testInvocation(t),
				ValidUntilLedger:  testValidUntilLedger,
				NetworkPassphrase: network.TestNetworkPassphrase,
			},
			wantErr: ErrMissingSigner,
		},
		{
			name: "a signer with no address",
			params: AuthorizeInvocationParams{
				Signer:            NewEd25519Signer(nil),
				Invocation:        testInvocation(t),
				ValidUntilLedger:  testValidUntilLedger,
				NetworkPassphrase: network.TestNetworkPassphrase,
			},
			wantMsg: "parse address",
		},
		{
			name: "a muxed signer address",
			params: AuthorizeInvocationParams{
				Signer: SignerFunc("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
					func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
						return xdr.ScVal{}, nil
					}),
				Invocation:        testInvocation(t),
				ValidUntilLedger:  testValidUntilLedger,
				NetworkPassphrase: network.TestNetworkPassphrase,
			},
			wantMsg: "muxed",
		},
		{
			name: "zero expiration",
			params: AuthorizeInvocationParams{
				Signer:            NewEd25519Signer(kp),
				Invocation:        testInvocation(t),
				ValidUntilLedger:  0,
				NetworkPassphrase: network.TestNetworkPassphrase,
			},
			wantErr: ErrInvalidExpiration,
		},
		{
			name: "empty network passphrase",
			params: AuthorizeInvocationParams{
				Signer:           NewEd25519Signer(kp),
				Invocation:       testInvocation(t),
				ValidUntilLedger: testValidUntilLedger,
			},
			wantMsg: "network passphrase is empty",
		},
		{
			name: "the signer fails",
			params: AuthorizeInvocationParams{
				Signer: SignerFunc(kp.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
					return xdr.ScVal{}, signerError
				}),
				Invocation:        testInvocation(t),
				ValidUntilLedger:  testValidUntilLedger,
				NetworkPassphrase: network.TestNetworkPassphrase,
			},
			wantErr: signerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthorizeInvocation(context.Background(), tt.params)
			if err == nil {
				t.Fatalf("AuthorizeInvocation succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected error %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: authorize invocation:") {
				t.Errorf("error %q is not wrapped as expected", err)
			}
		})
	}
}

func TestAuthorizeInvocationHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := AuthorizeInvocation(ctx, AuthorizeInvocationParams{
		Signer:            NewEd25519Signer(testKeypair(t, "soroauth-invocation-signer")),
		Invocation:        testInvocation(t),
		ValidUntilLedger:  testValidUntilLedger,
		NetworkPassphrase: network.TestNetworkPassphrase,
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not match context.Canceled", err)
	}
}
