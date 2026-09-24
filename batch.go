package soroauth

import (
	"bytes"
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// signersForEntry returns the signers whose address appears somewhere in the
// entry, in the order they were supplied, together with whether the top-level
// node is among the addresses matched.
func signersForEntry(entry xdr.SorobanAuthorizationEntry, signers []Signer) (matched []Signer, topLevelMatched bool, err error) {
	local := entry
	nodes, err := credentialNodes(&local)
	if err != nil {
		return nil, false, err
	}
	if len(nodes) == 0 {
		return nil, false, fmt.Errorf("entry has no credential nodes")
	}
	// credentialNodes always puts the top-level node first.
	topLevel := nodes[0].encoded

	for _, signer := range signers {
		if signer == nil {
			continue
		}
		address, parseErr := ParseAddress(signer.Address())
		if parseErr != nil {
			// A signer this batch cannot address simply matches nothing; if
			// that leaves an entry unsigned, the caller hears about it below.
			continue
		}
		encoded, encodeErr := addressBytes(address)
		if encodeErr != nil {
			return nil, false, encodeErr
		}

		for _, node := range nodes {
			if bytes.Equal(node.encoded, encoded) {
				matched = append(matched, signer)
				if bytes.Equal(encoded, topLevel) {
					topLevelMatched = true
				}
				break
			}
		}
	}

	return matched, topLevelMatched, nil
}

// AuthorizeAll signs every entry in a batch, or none of them.
//
// Source-account entries pass through unchanged, so a caller can hand over
// exactly what simulation returned without sorting the entries by arm first.
//
// Every other entry must be signed by someone. An entry that goes out unsigned
// produces a transaction that is accepted, charged for, and then fails during
// application, so an entry with no applicable signer fails the whole call with
// ErrMissingSigner naming its address. Nothing is ever skipped quietly.
//
// On any error the returned slice is nil. There is no partial result: a caller
// cannot accidentally submit a batch that is half signed.
//
// For the legacy and V2 arms, which have exactly one node, that means a signer
// whose Address() equals the entry's address. For the delegates arm, every
// signer whose address appears anywhere in the tree is applied, each targeted
// with ForAddress, and one matching signer anywhere in the tree is enough.
//
// What that means in practice, and it matters before submission: a delegate
// node with no matching signer is left unsigned. AuthorizeAll does not fail for
// it, because it cannot know whether that delegate's signature was required —
// a 2-of-3 delegate policy is legitimate, and so is a tree where only one
// branch needs to sign.
//
// When an unsigned node does fail is a protocol question, not a guess. Under
// CAP-71-01 ("Semantics", the delegate_account_auth function), a delegate node
// is only exercised if the account's own __check_auth calls
// delegate_account_auth for that address; the host then calls that delegate's
// __check_auth with the signature stored on the node. An unsigned node that is
// never delegated to costs nothing, while an unsigned node that is delegated to
// hands the delegate an empty signature — which a G-account delegate cannot
// authenticate with.
//
// In practice that second case is the one to expect. The CAP's own guidance on
// get_delegated_signers_for_current_auth_check says the account contract must
// check that the signers belong to it "and perform authentication for every one
// of them via delegate_account_auth", which is what soroban-sdk's delegate_auth
// documentation describes and what the modular-account fixture in e2e/ does.
//
// So unless you know your account's policy, treat an unsigned node as one that
// will fail: check the per-node Signed flags that Inspect reports before
// submitting, rather than reading a nil error here as "fully signed".
//
// That last rule is a deliberate reading of an ambiguity in the specification,
// which asks both that every address entry have a signer for its top-level
// address and that the delegates arm be signed through the tree. Requiring a
// top-level signature would make the delegates arm unusable in the exact case
// it was designed for: CAP-71-01 permits a Void top-level signature when the
// account authenticates purely through its delegates, and an entry built that
// way is complete without the account signing anything. soroauth cannot know
// an account's delegation policy — how many delegates it requires, or whether
// it requires its own key as well — so it enforces what it can check, that the
// entry is not going out with nothing signed at all, and leaves the policy to
// the caller who supplies the signers.
//
// ctx is checked before the first entry, including an empty batch, so a
// cancelled context fails closed even when no Signer would run. The same ctx
// is passed unchanged to AuthorizeEntry and from there to Signer.Sign.
func AuthorizeAll(
	ctx context.Context,
	entries []xdr.SorobanAuthorizationEntry,
	signers []Signer,
	validUntilLedger uint32,
	networkPassphrase string,
) ([]xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soroauth: authorize all: %w", err)
	}

	out := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))

	for i, entry := range entries {
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			copied, err := xdrcopy.Copy(entry)
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
			}
			out = append(out, copied)
			continue
		}

		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
		}
		address, err := FormatAddress(credentials.Address)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
		}

		matched, _, err := signersForEntry(entry, signers)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): %w", i, address, err)
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): %w", i, address,
				&MissingSignerError{Address: address})
		}

		signed := entry
		for _, signer := range matched {
			signed, err = AuthorizeEntry(ctx, signed, signer, validUntilLedger, networkPassphrase,
				ForAddress(signer.Address()))
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): signer %s: %w",
					i, address, signer.Address(), err)
			}
		}

		out = append(out, signed)
	}

	return out, nil
}
