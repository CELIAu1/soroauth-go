package readmesnippets

import (
	"context"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Delegates backs the README's "Delegates" section; see Quickstart's doc
// comment for how the snippet markers relate to README.md.
func Delegates(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	validUntil uint32,
	passphrase string,
	d1, d2, d3 string,
	k1, k2, k3 *keypair.Full,
) (xdr.SorobanAuthorizationEntry, error) {
	// snippet:start delegates
	wrapped, err := soroauth.WithDelegates(entry, validUntil,
		[]soroauth.Delegate{
			{Address: d1},
			{Address: d2, Nested: []soroauth.Delegate{{Address: d3}}},
		}, nil) // nil top-level signature → ScvVoid, which CAP-71-01 permits
	if err != nil {
		return wrapped, err
	}

	for _, kp := range []*keypair.Full{k1, k2, k3} {
		wrapped, err = soroauth.AuthorizeEntry(ctx, wrapped,
			soroauth.NewEd25519Signer(kp), validUntil, passphrase,
			soroauth.ForAddress(kp.Address()))
		if err != nil {
			return wrapped, err
		}
	}
	// snippet:end delegates
	return wrapped, nil
}
