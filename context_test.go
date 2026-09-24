package soroauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// cancelledContext returns an already-cancelled context.
func cancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancelledContext: ctx.Err() is not context.Canceled")
	}
	return ctx
}

// mustNotSign is a Signer that fails the test if Sign is ever called. It is
// the probe for "cancellation was checked before the signer ran".
func mustNotSign(t *testing.T, address string) Signer {
	t.Helper()
	return SignerFunc(address, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		t.Error("Signer.Sign was called despite a cancelled context")
		return xdr.ScVal{}, errors.New("must not sign")
	})
}

// ctxValueKey is the context key used to prove the *same* context — not a
// derived or replaced one — reaches Signer.Sign.
type ctxValueKey struct{}

// TestAuthorizeEntryHonoursContextCancellation covers AuthorizeEntry on every
// arm: a cancelled context must fail closed with context.Canceled, and the
// signer must not run, including the source-account path that never signs.
func TestAuthorizeEntryHonoursContextCancellation(t *testing.T) {
	// entryForArm always names "soroauth-preimage-signer"; the probe fails
	// the test if Sign is reached at all.
	entryAddress := testKeypair(t, "soroauth-preimage-signer").Address()
	otherAddress := testKeypair(t, "soroauth-ctx-entry").Address()
	ctx := cancelledContext(t)

	tests := []struct {
		name    string
		arm     xdr.SorobanCredentialsType
		probeAs string // address the probe signer claims
	}{
		{"address v2 with a matching signer", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, entryAddress},
		{"address v2 with a non-matching signer", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, otherAddress},
		{"legacy address", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, entryAddress},
		{"source account never reaches a signer", xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, entryAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := entryForArm(t, tt.arm, 42)
			probe := mustNotSign(t, tt.probeAs)

			got, err := AuthorizeEntry(ctx, entry, probe, testValidUntilLedger, network.TestNetworkPassphrase)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("error %v does not match context.Canceled", err)
			}
			if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
				t.Error("AuthorizeEntry returned an entry alongside a cancellation error")
			}
		})
	}
}

// TestAuthorizeEntryPassesContextToSigner proves AuthorizeEntry hands the
// caller's context — same cancellation, same values — to Signer.Sign.
func TestAuthorizeEntryPassesContextToSigner(t *testing.T) {
	kp := testKeypair(t, "soroauth-preimage-signer")
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	var gotValue string
	var gotErr error
	signer := SignerFunc(kp.Address(), func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		gotValue, _ = ctx.Value(ctxValueKey{}).(string)
		gotErr = ctx.Err()
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
	})

	ctx := context.WithValue(context.Background(), ctxValueKey{}, "entry-marker")
	if _, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
		t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
	}
	if gotValue != "entry-marker" {
		t.Errorf("Sign received context value %q, want %q — AuthorizeEntry replaced or dropped the context", gotValue, "entry-marker")
	}
	if gotErr != nil {
		t.Errorf("Sign received a cancelled context: %v", gotErr)
	}
}

// TestAuthorizeAllHonoursContextCancellation covers AuthorizeAll: a cancelled
// context must fail closed with context.Canceled and a nil result — including
// the empty batch, where no signer would ever run — and no signer may be
// invoked.
func TestAuthorizeAllHonoursContextCancellation(t *testing.T) {
	kp := testKeypair(t, "soroauth-ctx-batch")
	ctx := cancelledContext(t)
	probe := mustNotSign(t, kp.Address())

	t.Run("non-empty batch", func(t *testing.T) {
		entries := []xdr.SorobanAuthorizationEntry{
			entryForSigner(t, "soroauth-preimage-signer", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
			entryForSigner(t, "soroauth-ctx-batch", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
		}
		got, err := AuthorizeAll(ctx, entries, []Signer{probe}, testValidUntilLedger, network.TestNetworkPassphrase)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v does not match context.Canceled", err)
		}
		if got != nil {
			t.Errorf("AuthorizeAll returned %d entries alongside a cancellation error, want nil", len(got))
		}
	})

	t.Run("source-account-only batch never reaches a signer", func(t *testing.T) {
		entries := []xdr.SorobanAuthorizationEntry{
			entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1),
		}
		got, err := AuthorizeAll(ctx, entries, []Signer{probe}, testValidUntilLedger, network.TestNetworkPassphrase)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v does not match context.Canceled", err)
		}
		if got != nil {
			t.Errorf("AuthorizeAll returned %d entries alongside a cancellation error, want nil", len(got))
		}
	})

	t.Run("empty batch", func(t *testing.T) {
		got, err := AuthorizeAll(ctx, nil, nil, testValidUntilLedger, network.TestNetworkPassphrase)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v does not match context.Canceled", err)
		}
		if got != nil {
			t.Errorf("AuthorizeAll returned %d entries alongside a cancellation error, want nil", len(got))
		}
	})
}

// TestAuthorizeAllPassesContextToSigner proves AuthorizeAll hands the
// caller's context — same values — through AuthorizeEntry to Signer.Sign.
func TestAuthorizeAllPassesContextToSigner(t *testing.T) {
	kp := testKeypair(t, "soroauth-preimage-signer")
	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-preimage-signer", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
	}

	var gotValue string
	signer := SignerFunc(kp.Address(), func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		gotValue, _ = ctx.Value(ctxValueKey{}).(string)
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
	})

	ctx := context.WithValue(context.Background(), ctxValueKey{}, "batch-marker")
	if _, err := AuthorizeAll(ctx, entries, []Signer{signer}, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}
	if gotValue != "batch-marker" {
		t.Errorf("Sign received context value %q, want %q — AuthorizeAll replaced or dropped the context", gotValue, "batch-marker")
	}
}

// TestAuthorizeAllStopsWhenContextCancelsMidBatch proves the context is
// re-checked per entry: cancelling during entry 0's Sign must fail entry 1
// with context.Canceled rather than signing it under a dead context.
func TestAuthorizeAllStopsWhenContextCancelsMidBatch(t *testing.T) {
	kp := testKeypair(t, "soroauth-ctx-midbatch")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-ctx-midbatch", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, "soroauth-ctx-midbatch", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	calls := 0
	signer := SignerFunc(kp.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		calls++
		if calls == 1 {
			cancel() // the caller abandons the batch after the first signature
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
	})

	got, err := AuthorizeAll(ctx, entries, []Signer{signer}, testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not match context.Canceled", err)
	}
	if got != nil {
		t.Errorf("AuthorizeAll returned %d entries alongside a cancellation error, want nil", len(got))
	}
	if calls != 1 {
		t.Errorf("Signer.Sign ran %d times, want 1 — entry 1 was signed under a cancelled context", calls)
	}
}

// TestAuthorizeInvocationHonoursContextCancellation covers AuthorizeInvocation:
// a cancelled context must fail closed with context.Canceled before any work,
// including nonce generation, and the signer must not run.
func TestAuthorizeInvocationHonoursContextCancellation(t *testing.T) {
	kp := testKeypair(t, "soroauth-ctx-invocation")
	ctx := cancelledContext(t)
	probe := mustNotSign(t, kp.Address())

	got, err := AuthorizeInvocation(ctx, AuthorizeInvocationParams{
		Signer:            probe,
		Invocation:        testInvocation(t),
		ValidUntilLedger:  testValidUntilLedger,
		NetworkPassphrase: network.TestNetworkPassphrase,
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not match context.Canceled", err)
	}
	if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
		t.Error("AuthorizeInvocation returned an entry alongside a cancellation error")
	}
}

// TestAuthorizeInvocationPassesContextToSigner proves AuthorizeInvocation
// hands the caller's context — same values — through AuthorizeEntry to
// Signer.Sign.
func TestAuthorizeInvocationPassesContextToSigner(t *testing.T) {
	kp := testKeypair(t, "soroauth-ctx-invocation-pass")

	var gotValue string
	signer := SignerFunc(kp.Address(), func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		gotValue, _ = ctx.Value(ctxValueKey{}).(string)
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
	})

	ctx := context.WithValue(context.Background(), ctxValueKey{}, "invocation-marker")
	if _, err := AuthorizeInvocation(ctx, AuthorizeInvocationParams{
		Signer:            signer,
		Invocation:        testInvocation(t),
		ValidUntilLedger:  testValidUntilLedger,
		NetworkPassphrase: network.TestNetworkPassphrase,
	}); err != nil {
		t.Fatalf("AuthorizeInvocation returned an unexpected error: %v", err)
	}
	if gotValue != "invocation-marker" {
		t.Errorf("Sign received context value %q, want %q — AuthorizeInvocation replaced or dropped the context", gotValue, "invocation-marker")
	}
}

// TestContextDeadlineAlsoFailsClosed: the rule is ctx.Err(), not only
// cancellation, so a deadline exceeded must be honoured the same way.
func TestContextDeadlineAlsoFailsClosed(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
	}

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	probe := mustNotSign(t, testKeypair(t, "soroauth-preimage-signer").Address())
	if _, err := AuthorizeEntry(ctx, entry, probe, testValidUntilLedger, network.TestNetworkPassphrase); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("AuthorizeEntry error %v does not match context.DeadlineExceeded", err)
	}
	if _, err := AuthorizeAll(ctx, []xdr.SorobanAuthorizationEntry{entry}, []Signer{probe},
		testValidUntilLedger, network.TestNetworkPassphrase); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("AuthorizeAll error %v does not match context.DeadlineExceeded", err)
	}
	if _, err := AuthorizeInvocation(ctx, AuthorizeInvocationParams{
		Signer: probe, Invocation: testInvocation(t),
		ValidUntilLedger: testValidUntilLedger, NetworkPassphrase: network.TestNetworkPassphrase,
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("AuthorizeInvocation error %v does not match context.DeadlineExceeded", err)
	}
}
