package soroauth

import (
	"fmt"
	"iter"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// CredentialNode represents one signature-bearing node in an authorization entry.
// It carries the address, the path within the entry (compatible with DiffEntries),
// and whether the node currently carries a signature.
type CredentialNode struct {
	// Address is the G… or C… strkey of the credential node.
	Address string

	// Path is the location of this node within the entry, using the same scheme
	// as DiffEntries: "credentials" for the top-level node,
	// "credentials.delegates[G…]" for a top-level delegate,
	// "credentials.delegates[G…].nested[G…]" for nested delegates.
	Path string

	// Signed reports whether the node's signature field holds a real signature
	// (neither ScvVoid nor an empty ScvVec).
	Signed bool
}

// CredentialNodes returns an iterator over every signature-bearing node in entry.
// The iterator yields the top-level node first, then every delegate at every depth
// in depth-first order, matching the order used by DiffEntries and VerifyEntry.
//
// The iterator is read-only: it does not expose pointers into the entry and
// cannot be used to write a signature. To modify a node, use AuthorizeEntry
// with ForAddress.
//
// The walk is bounded by MaxDecodeDepth. An entry nested beyond that limit
// causes the iterator to stop and return ErrDecodeLimit.
//
// Iteration order is stable and documented: top-level node first, then
// delegates at each level in stored (ascending address) order, recursing into
// nested delegates before moving to the next sibling.
//
// This function uses iter.Seq (available in Go 1.23+). The iterator may return
// an error, which will be the final value yielded when ranging over it.
//
// Example:
//
//	for node, err := range soroauth.CredentialNodes(entry) {
//	    if err != nil {
//	        return err
//	    }
//	    fmt.Printf("%s: %s (signed=%v)\n", node.Path, node.Address, node.Signed)
//	}
func CredentialNodes(entry xdr.SorobanAuthorizationEntry) iter.Seq2[CredentialNode, error] {
	return func(yield func(CredentialNode, error) bool) {
		// Source-account entries have no credential nodes of their own.
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			return
		}

		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			yield(CredentialNode{}, fmt.Errorf("soroauth: credential nodes: %w", err))
			return
		}

		address, err := FormatAddress(credentials.Address)
		if err != nil {
			yield(CredentialNode{}, fmt.Errorf("soroauth: credential nodes: %w", err))
			return
		}

		topNode := CredentialNode{
			Address: address,
			Path:    "credentials",
			Signed:  isSigned(credentials.Signature),
		}
		if !yield(topNode, nil) {
			return
		}

		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
			if err := yieldDelegateNodes(entry.Credentials.AddressWithDelegates.Delegates, "credentials.delegates", 1, yield); err != nil {
				yield(CredentialNode{}, fmt.Errorf("soroauth: credential nodes: %w", err))
			}
		}
	}
}

// yieldDelegateNodes recursively yields delegate nodes with their paths.
// prefix is the path prefix (e.g., "credentials.delegates").
// depth is the current nesting depth (1 for top-level delegates).
func yieldDelegateNodes(delegates []xdr.SorobanDelegateSignature, prefix string, depth int, yield func(CredentialNode, error) bool) error {
	if err := checkTraversalDepth(depth); err != nil {
		return err
	}

	seen := make(map[string]int, len(delegates))
	for i := range delegates {
		address, err := FormatAddress(delegates[i].Address)
		if err != nil {
			return err
		}

		// Use the same duplicate-handling logic as diff.go.
		path := fmt.Sprintf("%s[%s]", prefix, address)
		seen[path]++
		if n := seen[path]; n > 1 {
			path = fmt.Sprintf("%s#%d", path, n)
		}

		node := CredentialNode{
			Address: address,
			Path:    path,
			Signed:  isSigned(delegates[i].Signature),
		}
		if !yield(node, nil) {
			return nil
		}

		if len(delegates[i].NestedDelegates) > 0 {
			if err := yieldDelegateNodes(delegates[i].NestedDelegates, path+".nested", depth+1, yield); err != nil {
				return err
			}
		}
	}
	return nil
}
