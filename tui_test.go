package soroauth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestTUIHonoursContextCancellation proves TUI checks ctx.Err() before doing
// work and fails closed with context.Canceled.
func TestTUIHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Use a valid base64 entry that will pass decoding but we'll never reach
	// the interactive part because we're not on a TTY.
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling entry: %v", err)
	}
	entryB64 := base64.StdEncoding.EncodeToString(entryBytes)

	// TUI requires a secret env var, but we'll hit the context check first.
	err = TUI(ctx, entryB64, testValidUntilLedger, network.TestNetworkPassphrase, "NONEXISTENT_ENV_VAR", "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not match context.Canceled", err)
	}
}

// TestTUIHonoursContextDeadline proves TUI also fails closed on a
// deadline-exceeded context.
func TestTUIHonoursContextDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling entry: %v", err)
	}
	entryB64 := base64.StdEncoding.EncodeToString(entryBytes)

	err = TUI(ctx, entryB64, testValidUntilLedger, network.TestNetworkPassphrase, "NONEXISTENT_ENV_VAR", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not match context.DeadlineExceeded", err)
	}
}

// TestTUIWithOutputHonoursContextCancellation covers the writer-injected entry
// point used by the CLI's --quiet mode.
func TestTUIWithOutputHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling entry: %v", err)
	}
	entryB64 := base64.StdEncoding.EncodeToString(entryBytes)

	err = TUIWithOutput(ctx, entryB64, testValidUntilLedger, network.TestNetworkPassphrase, "NONEXISTENT_ENV_VAR", "", io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not match context.Canceled", err)
	}
}
