package readmesnippets

import (
	"context"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// AllowResignExample backs the README's inline AllowResign example in the
// "Delegates" section; see Quickstart's doc comment for how the snippet
// markers relate to README.md.
func AllowResignExample(
	ctx context.Context,
	wrapped xdr.SorobanAuthorizationEntry,
	k1 *keypair.Full,
	validUntil uint32,
	passphrase string,
	d1 string,
) (xdr.SorobanAuthorizationEntry, error) {
	// snippet:start allowresign
	resigned, err := soroauth.AuthorizeEntry(ctx, wrapped, soroauth.NewEd25519Signer(k1),
		validUntil, passphrase, soroauth.ForAddress(d1), soroauth.AllowResign(d1))
	// snippet:end allowresign
	return resigned, err
}
