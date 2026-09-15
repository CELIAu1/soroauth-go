package soroauth

import (
	"bytes"
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// authorizeConfig holds the optional behaviour of AuthorizeEntry.
type authorizeConfig struct {
	targetAddress string
	hasTarget     bool
	allowResign   bool
}

// AuthorizeOption adjusts how AuthorizeEntry behaves.
type AuthorizeOption func(*authorizeConfig)

// ForAddress names the credential node the signature is written onto, for the
// case where the signing key does not belong to the address being authorized.
//
// It is needed for the delegates arm, where one key may be signing on behalf of
// a delegate several levels down, and for a classic account whose signer is a
// different account. Without it the target is the signer's own Address().
//
// Naming an address that appears nowhere in the entry is an error
// (ErrNoMatchingCredentialNode), never a silent no-op.
func ForAddress(addr string) AuthorizeOption {
	return func(c *authorizeConfig) {
		c.targetAddress = addr
		c.hasTarget = true
	}
}

// AllowResign permits writing over a credential node that already carries a
// signature.
//
// Without it, overwriting is refused with ErrAlreadySigned. The reason is
// CAP-71-01: in a delegates entry every signature-bearing node commits to the
// same payload, and that payload includes the expiration ledger, so re-signing
// one node under a different expiration silently invalidates every other node's
// signature. The entry then still looks complete and fails only on-chain.
//
// Even with AllowResign, the delegates arm refuses to re-sign at an expiration
// that disagrees with one already committed to by other signatures.
func AllowResign() AuthorizeOption {
	return func(c *authorizeConfig) { c.allowResign = true }
}

// isSigned reports whether a credential node's signature field holds a real
// signature rather than a placeholder.
//
// Both placeholders occur in practice: CAP-71-01 permits a Void top-level
// signature when only delegates authenticate, and simulation and the JS
// reference both use an empty vector as the "to be filled in" value.
func isSigned(value xdr.ScVal) bool {
	switch value.Type {
	case xdr.ScValTypeScvVoid:
		return false
	case xdr.ScValTypeScvVec:
		if value.Vec == nil || *value.Vec == nil {
			return false
		}
		return len(**value.Vec) > 0
	default:
		return true
	}
}

// addressBytes returns the XDR encoding of an address, which is how addresses
// are compared throughout this library. Comparing encodings rather than strkey
// strings means the comparison is over the same bytes the protocol orders and
// the host checks.
func addressBytes(a xdr.ScAddress) ([]byte, error) {
	encoded, err := a.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encoding address: %w", err)
	}
	return encoded, nil
}

// matchingSignatures returns pointers to the signature field of every
// credential node in entry whose address equals target.
//
// The pointers are into entry, so writing through them fills the entry in
// place; callers pass a copy they own.
func matchingSignatures(entry *xdr.SorobanAuthorizationEntry, target []byte) ([]*xdr.ScVal, error) {
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return nil, err
	}

	var matches []*xdr.ScVal

	topLevel, err := addressBytes(credentials.Address)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(topLevel, target) {
		matches = append(matches, &credentials.Signature)
	}

	return matches, nil
}

// AuthorizeEntry signs entry and returns a signed copy, leaving entry
// untouched.
//
// Source-account entries are returned unchanged with a nil error rather than
// rejected, so a caller can pass every entry simulation returned straight
// through without sorting them by arm first. This matches the JS reference.
//
// The address whose credential node receives the signature is the one named by
// ForAddress, or the signer's own Address() when that option is absent. This is
// a deliberate difference from the JS reference, which writes to the top-level
// node when no target is given even if the key belongs to someone else.
// soroauth only ever writes a signature onto a node whose address equals the
// target, and returns ErrNoMatchingCredentialNode when nothing matches, because
// a signature written onto the wrong node is a transaction that pays fees and
// then fails, or worse, authorizes something the key holder did not intend.
//
// validUntilLedger is both signed over and written into the returned entry's
// top-level SignatureExpirationLedger, so the two can never disagree. The host
// rejects an entry once the current ledger is past that value, and also rejects
// a value above the network's max_live_until_ledger, which this library cannot
// know offline and therefore does not cap.
//
// A node that already carries a signature is not overwritten unless the caller
// passes AllowResign; see that option for why.
func AuthorizeEntry(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	signer Signer,
	validUntilLedger uint32,
	networkPassphrase string,
	opts ...AuthorizeOption,
) (xdr.SorobanAuthorizationEntry, error) {
	var config authorizeConfig
	for _, opt := range opts {
		opt(&config)
	}

	// Source-account entries carry no signature of their own; the transaction
	// envelope covers them. Hand back a copy so the caller's input is never
	// shared with the result.
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		copied, err := xdrcopy.Copy(entry)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
		}
		return copied, nil
	}

	if _, err := addressCredentials(entry.Credentials); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	if validUntilLedger == 0 {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: authorize entry: expiration ledger is zero: %w", ErrInvalidExpiration)
	}

	if signer == nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", ErrMissingSigner)
	}

	target := signer.Address()
	if config.hasTarget {
		target = config.targetAddress
	}
	if target == "" {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: authorize entry: no target address; the signer has none and ForAddress was not given: %w",
			ErrMissingSigner)
	}
	targetAddress, err := ParseAddress(target)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}
	targetEncoded, err := addressBytes(targetAddress)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	// Work on a copy from here on, so the caller's entry is never written to
	// and nothing partial can escape alongside an error.
	signed, err := xdrcopy.Copy(entry)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	matches, err := matchingSignatures(&signed, targetEncoded)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}
	if len(matches) == 0 {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: authorize entry: %s: %w", target, ErrNoMatchingCredentialNode)
	}

	// Checked before signing rather than after, so a remote signer is never
	// asked to sign something that is about to be thrown away.
	if !config.allowResign {
		for _, match := range matches {
			if isSigned(*match) {
				return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
					"soroauth: authorize entry: %s: %w", target, ErrAlreadySigned)
			}
		}
	}

	preimage, err := Preimage(signed, validUntilLedger, networkPassphrase)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	signature, err := signer.Sign(ctx, preimage, payload)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	// The expiration written into the credentials must be the one that was
	// signed over, or the host recomputes a different payload and rejects it.
	credentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}
	credentials.SignatureExpirationLedger = xdr.Uint32(validUntilLedger)

	for _, match := range matches {
		*match = signature
	}

	return signed, nil
}
