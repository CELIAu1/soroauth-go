package soroauth

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// AuthorizeInvocationParams are the inputs to AuthorizeInvocation.
type AuthorizeInvocationParams struct {
	// Signer produces the signature and, unless the invocation names a
	// different address, identifies the account being authorized.
	Signer Signer

	// Invocation is the call tree being approved.
	Invocation xdr.SorobanAuthorizedInvocation

	// ValidUntilLedger is the last ledger at which the signature is accepted.
	// The host rejects the entry once the current ledger is past it, so the
	// value itself is still valid.
	ValidUntilLedger uint32

	// NetworkPassphrase identifies the network the signature is bound to.
	NetworkPassphrase string

	// Legacy builds SOROBAN_CREDENTIALS_ADDRESS instead of the default
	// SOROBAN_CREDENTIALS_ADDRESS_V2. The zero value is therefore V2.
	Legacy bool
}

// newNonce returns a fresh nonce: eight bytes from crypto/rand read as a
// big-endian signed int64.
//
// The nonce is what makes a signature single-use — the host consumes it, so a
// repeat is rejected. It is therefore read from crypto/rand and nowhere else. A
// read failure is returned as an error rather than falling back to a weaker
// source, because a predictable nonce is a signature an attacker can anticipate.
//
// The value is signed, so roughly half of all nonces are negative. That is
// normal and is covered by the legacy_negative_nonce golden vector.
func newNonce() (xdr.Int64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("reading a random nonce: %w", err)
	}
	return xdr.Int64(int64(binary.BigEndian.Uint64(buf[:]))), nil
}

// AuthorizeInvocation builds a fresh authorization entry for an invocation tree
// and signs it, for callers who are constructing the call themselves rather
// than authorizing one that simulation returned.
//
// The credentials arm defaults to SOROBAN_CREDENTIALS_ADDRESS_V2, which binds
// the signer's address into the signed payload (CAP-71-01). This matches
// @stellar/stellar-sdk@17.1.0, whose authorizeInvocation defaults authV2 to
// true (src/base/auth.ts:442). Set Legacy to build
// SOROBAN_CREDENTIALS_ADDRESS instead.
//
// The nonce is generated here; see newNonce. Everything else is delegated to
// AuthorizeEntry, so the target-address rule, the expiration handling and the
// deep-copy guarantee are all identical to authorizing a simulated entry.
//
// ctx is checked before any work, including nonce generation, so a cancelled
// context fails closed without consuming entropy. The same ctx is passed
// unchanged to AuthorizeEntry and from there to Signer.Sign.
func AuthorizeInvocation(ctx context.Context, p AuthorizeInvocationParams) (xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize invocation: %w", err)
	}
	if p.Signer == nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: authorize invocation: %w", ErrMissingSigner)
	}

	address, err := ParseAddress(p.Signer.Address())
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize invocation: %w", err)
	}

	nonce, err := newNonce()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize invocation: %w", err)
	}

	credentials := xdr.SorobanAddressCredentials{
		Address: address,
		Nonce:   nonce,
		// Both are placeholders. AuthorizeEntry writes the real expiration,
		// which is also the value it signs over, and the signature.
		SignatureExpirationLedger: 0,
		Signature:                 scVec(),
	}

	entry := xdr.SorobanAuthorizationEntry{
		RootInvocation: p.Invocation,
	}
	if p.Legacy {
		entry.Credentials = xdr.SorobanCredentials{
			Type:    xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &credentials,
		}
	} else {
		entry.Credentials = xdr.SorobanCredentials{
			Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &credentials,
		}
	}

	signed, err := AuthorizeEntry(ctx, entry, p.Signer, p.ValidUntilLedger, p.NetworkPassphrase)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize invocation: %w", err)
	}
	return signed, nil
}
