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
	targetAddress        string
	hasTarget            bool
	allowResign          bool
	allowResignAddresses []string
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
// With no arguments, AllowResign lifts the guard for whatever address this
// call targets (ForAddress, or the signer's own Address()) — the original,
// unscoped behaviour. With one or more addresses, it lifts the guard only when
// the call's target is among them; a target that is not named still refuses
// with ErrAlreadySigned even though AllowResign was passed. This matters for a
// caller replacing one party's signature in a delegates entry: without
// scoping, a single AllowResign() shared across every AuthorizeEntry call in
// the batch would also silently permit overwriting every other delegate's
// signature, not just the one being replaced. Naming the address makes the
// permission specific to that node.
//
// Every address is parsed with ParseAddress and compared by the address's XDR
// encoding, the same comparison AuthorizeEntry uses to find a target's
// credential node, so a malformed address is rejected rather than silently
// never matching.
//
// Even with AllowResign, and regardless of scoping, the delegates arm refuses
// to re-sign at an expiration that disagrees with one already committed to by
// other signatures: that guard protects the *other* nodes, not the one named
// here, so no address list can lift it.
func AllowResign(addresses ...string) AuthorizeOption {
	return func(c *authorizeConfig) {
		c.allowResign = true
		c.allowResignAddresses = addresses
	}
}

// resignAllowedFor reports whether AllowResign's scope covers target, given
// its XDR-encoded address and the encoded addresses AllowResign named. An
// empty scope means AllowResign was given no addresses, so it is unscoped.
func resignAllowedFor(targetEncoded []byte, scope [][]byte) bool {
	if len(scope) == 0 {
		return true
	}
	for _, encoded := range scope {
		if bytes.Equal(targetEncoded, encoded) {
			return true
		}
	}
	return false
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

// credentialNode is one signature-bearing node of an entry: the XDR encoding
// of the address it belongs to, and a pointer to the signature field itself.
type credentialNode struct {
	encoded   []byte
	signature *xdr.ScVal
}

// delegateNodesOf flattens a delegates array and everything nested under it.
//
// Under CAP-71-01 a delegate may itself delegate, to any depth, and every one
// of those nodes signs the same payload. So a signer's address can legitimately
// appear at several depths at once, and all of them must be filled.
func delegateNodesOf(nodes []xdr.SorobanDelegateSignature) ([]credentialNode, error) {
	var out []credentialNode
	for i := range nodes {
		encoded, err := addressBytes(nodes[i].Address)
		if err != nil {
			return nil, err
		}
		// &nodes[i].Signature points into the caller's slice, which is the
		// entry being filled in; the slice is never regrown here.
		out = append(out, credentialNode{encoded: encoded, signature: &nodes[i].Signature})

		nested, err := delegateNodesOf(nodes[i].NestedDelegates)
		if err != nil {
			return nil, err
		}
		out = append(out, nested...)
	}
	return out, nil
}

// credentialNodes returns every signature-bearing node in entry: the top-level
// node always, plus every delegate at every depth for the delegates arm.
//
// The pointers are into entry, so writing through them fills the entry in
// place; callers pass a copy they own.
func credentialNodes(entry *xdr.SorobanAuthorizationEntry) ([]credentialNode, error) {
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return nil, err
	}

	topLevel, err := addressBytes(credentials.Address)
	if err != nil {
		return nil, err
	}
	nodes := []credentialNode{{encoded: topLevel, signature: &credentials.Signature}}

	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		delegates, err := delegateNodesOf(entry.Credentials.AddressWithDelegates.Delegates)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, delegates...)
	}

	return nodes, nil
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
//
// ctx is checked before any work, including the source-account pass-through,
// so a cancelled context fails closed even on a path that never reaches a
// Signer. The same ctx is passed unchanged to signer.Sign.
func AuthorizeEntry(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	signer Signer,
	validUntilLedger uint32,
	networkPassphrase string,
	opts ...AuthorizeOption,
) (xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

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

	// AllowResign's scope is resolved against parsed addresses, the same way
	// the target is, so a malformed address here fails closed rather than
	// silently never matching.
	var allowResignScope [][]byte
	for _, addr := range config.allowResignAddresses {
		parsed, err := ParseAddress(addr)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
				"soroauth: authorize entry: AllowResign address %q: %w", addr, err)
		}
		encoded, err := addressBytes(parsed)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
		}
		allowResignScope = append(allowResignScope, encoded)
	}
	resignAllowed := config.allowResign && resignAllowedFor(targetEncoded, allowResignScope)

	// Work on a copy from here on, so the caller's entry is never written to
	// and nothing partial can escape alongside an error.
	signed, err := xdrcopy.Copy(entry)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	existingCredentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	isDelegates := signed.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates

	// A delegates entry whose arrays are mis-ordered is rejected by the host,
	// so it is checked before a signature exists rather than after fees are
	// paid (CAP-71-01).
	if isDelegates {
		if err := ValidateDelegateOrder(signed); err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
		}
	}

	nodes, err := credentialNodes(&signed)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize entry: %w", err)
	}

	var matches []*xdr.ScVal
	for _, node := range nodes {
		if bytes.Equal(node.encoded, targetEncoded) {
			matches = append(matches, node.signature)
		}
	}
	if len(matches) == 0 {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: authorize entry: %s: %w", target,
			&NoMatchingCredentialNodeError{Address: target})
	}

	// In a delegates entry every signature-bearing node commits to one shared
	// payload that includes the expiration ledger (CAP-71-01). So once any
	// node is signed, the expiration is fixed: signing another node at a
	// different expiration would produce an entry whose signatures disagree
	// about what they authorized, and the host would reject it. AllowResign
	// does not lift this, because the damage is to the other nodes, not this
	// one.
	if isDelegates {
		stored := uint32(existingCredentials.SignatureExpirationLedger)
		if stored != validUntilLedger {
			for _, node := range nodes {
				if isSigned(*node.signature) {
					return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
						"soroauth: authorize entry: the entry already carries signatures over expiration %d, "+
							"but %d was requested: %w",
						stored, validUntilLedger, ErrInvalidExpiration)
				}
			}
		}
	}

	// Checked before signing rather than after, so a remote signer is never
	// asked to sign something that is about to be thrown away.
	if !resignAllowed {
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
	existingCredentials.SignatureExpirationLedger = xdr.Uint32(validUntilLedger)

	for _, match := range matches {
		*match = signature
	}

	return signed, nil
}
