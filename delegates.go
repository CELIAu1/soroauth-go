package soroauth

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// Delegate describes one delegated signer to attach to an entry.
//
// A delegate is an address the account has authorized to sign on its behalf.
// Under CAP-71-01 the account and every delegate, at every nesting depth, all
// sign the same payload, which is bound to the top-level account address.
type Delegate struct {
	// Address is the delegate's G… account or C… contract address.
	Address string

	// Signature is the delegate's signature value. A nil Signature becomes an
	// ScvVoid placeholder, to be filled in later by AuthorizeEntry with
	// ForAddress(this address).
	Signature *xdr.ScVal

	// Nested holds signers this delegate in turn delegates to. The tree may be
	// arbitrarily deep.
	Nested []Delegate
}

// delegateNode pairs a built node with the encoded address it sorts on, so the
// encoding happens once and its error is handled outside the sort comparator.
type delegateNode struct {
	node    xdr.SorobanDelegateSignature
	encoded []byte
}

// sortDelegateLevel orders one delegates array by the XDR encoding of each
// address, ascending, and rejects a repeat within that array.
//
// CAP-71-01 requires each delegates array to be in increasing address order,
// which leaves no room for a duplicate at the same level. The same address at
// two different levels is a different thing and is allowed, so the check is
// per-array and never across levels.
//
// The comparison is over XDR bytes rather than strkey strings. The JS reference
// sorts the same way, with compareUint8Arrays over address.toXdr()
// (@stellar/stellar-sdk@17.1.0 src/base/auth.ts:655-657), and that function is
// byte-wise lexicographic with a shorter-first tiebreak
// (uint8array-extras index.js:94-110), which is exactly bytes.Compare.
func sortDelegateLevel(nodes []delegateNode) error {
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].encoded, nodes[j].encoded) < 0
	})

	for i := 1; i < len(nodes); i++ {
		if bytes.Equal(nodes[i-1].encoded, nodes[i].encoded) {
			address, err := FormatAddress(nodes[i].node.Address)
			if err != nil {
				address = "<unformattable address>"
			}
			return fmt.Errorf("%s: %w", address, &DuplicateDelegateError{Address: address})
		}
	}
	return nil
}

// buildDelegateNodes converts Delegate descriptors into XDR nodes, recursively,
// sorting and de-duplicating each level as it goes.
func buildDelegateNodes(delegates []Delegate) ([]xdr.SorobanDelegateSignature, error) {
	if len(delegates) == 0 {
		return nil, nil
	}

	built := make([]delegateNode, 0, len(delegates))
	for _, delegate := range delegates {
		address, err := ParseAddress(delegate.Address)
		if err != nil {
			return nil, err
		}
		encoded, err := addressBytes(address)
		if err != nil {
			return nil, err
		}

		signature := xdr.ScVal{Type: xdr.ScValTypeScvVoid}
		if delegate.Signature != nil {
			signature = *delegate.Signature
		}

		nested, err := buildDelegateNodes(delegate.Nested)
		if err != nil {
			return nil, err
		}

		built = append(built, delegateNode{
			node: xdr.SorobanDelegateSignature{
				Address:         address,
				Signature:       signature,
				NestedDelegates: nested,
			},
			encoded: encoded,
		})
	}

	if err := sortDelegateLevel(built); err != nil {
		return nil, err
	}

	nodes := make([]xdr.SorobanDelegateSignature, 0, len(built))
	for _, item := range built {
		nodes = append(nodes, item.node)
	}
	return nodes, nil
}

// WithDelegates wraps an entry's address credentials in a
// SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES arm carrying the given delegate
// tree, returning a new entry and leaving the input untouched.
//
// Simulation never produces the delegates arm on its own: which addresses an
// account delegates to is account-specific policy that only the client knows,
// much like a multisig policy. This function assembles the wrapper; the
// signatures are filled in afterwards with AuthorizeEntry and ForAddress.
//
// Both the legacy and V2 arms may be wrapped. Note what that means for a legacy
// entry: the delegates arm is address-bound, so wrapping a legacy entry changes
// its signing payload from ENVELOPE_TYPE_SOROBAN_AUTHORIZATION to
// ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS (CAP-71-01). Anything signed
// before the wrap no longer verifies, which is why an already-signed entry is
// refused with ErrAlreadySigned. The ScvVoid and empty-ScvVec placeholders that
// simulation emits are not signatures and are accepted.
//
// topSignature is the account's own signature. Passing nil stores ScvVoid,
// which CAP-71-01 permits for an account that authenticates purely through its
// delegates.
//
// Each delegates array, at every depth, is sorted by address and checked for
// duplicates; see sortDelegateLevel.
func WithDelegates(
	entry xdr.SorobanAuthorizationEntry,
	validUntilLedger uint32,
	delegates []Delegate,
	topSignature *xdr.ScVal,
) (xdr.SorobanAuthorizationEntry, error) {
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		// the two wrappable arms
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: with delegates: source-account credentials carry no address to wrap: %w",
			ErrUnsupportedCredentials)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: with delegates: the entry already uses the delegates arm: %w",
			ErrUnsupportedCredentials)
	default:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: with delegates: %w", ErrUnsupportedCredentials)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: with delegates: %w", err)
	}

	// Resolved fail-closed: a zero expiration is already expired by the host's
	// rule (current ledger > stored value is rejected), so storing it would
	// build an entry that can never be applied.
	if validUntilLedger == 0 {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: with delegates: expiration ledger is zero: %w", ErrInvalidExpiration)
	}

	if isSigned(credentials.Signature) {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: with delegates: wrapping changes the signing payload, invalidating the existing signature: %w",
			ErrAlreadySigned)
	}

	nodes, err := buildDelegateNodes(delegates)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: with delegates: %w", err)
	}

	signature := xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	if topSignature != nil {
		signature = *topSignature
	}

	wrapped := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   credentials.Address,
					Nonce:                     credentials.Nonce,
					SignatureExpirationLedger: xdr.Uint32(validUntilLedger),
					Signature:                 signature,
				},
				Delegates: nodes,
			},
		},
		RootInvocation: entry.RootInvocation,
	}

	// The value above still points into the caller's entry through the
	// invocation tree and the address, and into the caller's ScVals.
	copied, err := xdrcopy.Copy(wrapped)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: with delegates: %w", err)
	}
	return copied, nil
}

// validateDelegateLevel checks one delegates array, then recurses.
func validateDelegateLevel(nodes []xdr.SorobanDelegateSignature) error {
	var previous []byte
	for i := range nodes {
		current, err := addressBytes(nodes[i].Address)
		if err != nil {
			return err
		}

		if previous != nil {
			switch bytes.Compare(previous, current) {
			case 0:
				address, err := FormatAddress(nodes[i].Address)
				if err != nil {
					address = "<unformattable address>"
				}
				return fmt.Errorf("%s: %w", address, &DuplicateDelegateError{Address: address})
			case 1:
				address, err := FormatAddress(nodes[i].Address)
				if err != nil {
					address = "<unformattable address>"
				}
				return fmt.Errorf(
					"delegates are not in ascending address order at index %d (%s)", i, address)
			}
		}
		previous = current

		if err := validateDelegateLevel(nodes[i].NestedDelegates); err != nil {
			return err
		}
	}
	return nil
}

// ValidateDelegateOrder checks that an existing delegates-arm entry satisfies
// CAP-71-01's ordering rule at every level: each delegates array in increasing
// address order, with no address repeated within an array.
//
// AuthorizeEntry calls this before signing a delegates entry. An entry that
// fails here would be rejected by the host, so catching it before a signature
// exists turns an on-chain failure that costs fees into a local error.
//
// Any arm other than the delegates arm returns ErrUnsupportedCredentials:
// there is no delegate ordering to check, and silently returning nil would let
// a caller believe an entry had been validated when nothing was examined.
func ValidateDelegateOrder(entry xdr.SorobanAuthorizationEntry) error {
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		return fmt.Errorf("soroauth: validate delegate order: %w", ErrUnsupportedCredentials)
	}
	if entry.Credentials.AddressWithDelegates == nil {
		return fmt.Errorf("soroauth: validate delegate order: address_with_delegates credentials arm is empty")
	}

	if err := validateDelegateLevel(entry.Credentials.AddressWithDelegates.Delegates); err != nil {
		return fmt.Errorf("soroauth: validate delegate order: %w", err)
	}
	return nil
}
