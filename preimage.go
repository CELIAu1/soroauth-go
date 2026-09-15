package soroauth

import (
	"crypto/sha256"
	"fmt"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// addressCredentials returns the xdr.SorobanAddressCredentials carried by any
// address-based credentials arm, which all three of them hold in the same
// shape: ADDRESS and ADDRESS_V2 are that struct directly, and
// ADDRESS_WITH_DELEGATES wraps it alongside the delegate tree.
//
// It returns ErrSourceAccountCredentials for the source-account arm and
// ErrUnsupportedCredentials for a discriminant outside the four defined ones,
// so callers can tell the two apart with errors.Is — AuthorizeEntry passes
// source-account entries through, while Preimage refuses them.
//
// The returned pointer aliases the entry it came from. It is for reading.
func addressCredentials(c xdr.SorobanCredentials) (*xdr.SorobanAddressCredentials, error) {
	switch c.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return nil, ErrSourceAccountCredentials

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if c.Address == nil {
			return nil, fmt.Errorf("address credentials arm is empty")
		}
		return c.Address, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		if c.AddressV2 == nil {
			return nil, fmt.Errorf("address_v2 credentials arm is empty")
		}
		return c.AddressV2, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if c.AddressWithDelegates == nil {
			return nil, fmt.Errorf("address_with_delegates credentials arm is empty")
		}
		return &c.AddressWithDelegates.AddressCredentials, nil

	default:
		return nil, ErrUnsupportedCredentials
	}
}

// Preimage builds the xdr.HashIdPreimage whose SHA-256 hash a signer must sign
// to authorize entry.
//
// Which preimage variant applies is decided by the credentials arm, because
// that is what the host will reconstruct when it verifies:
//
//   - SOROBAN_CREDENTIALS_ADDRESS (CAP-46-11) gets the legacy
//     ENVELOPE_TYPE_SOROBAN_AUTHORIZATION variant, which does not name the
//     signing address.
//   - SOROBAN_CREDENTIALS_ADDRESS_V2 and SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES
//     (CAP-71-01) get ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS, which
//     binds the address into the signed bytes. That binding is what closes the
//     replay case where one key is shared across several accounts and the
//     contract does not itself bind the address into its arguments.
//   - SOROBAN_CREDENTIALS_SOURCE_ACCOUNT has no payload at all and returns
//     ErrSourceAccountCredentials; the transaction envelope's signature covers
//     it.
//
// For the delegates arm the address bound in is the *top-level* address, and
// this one payload is what the top-level account and every delegate at every
// nesting depth each sign (CAP-71-01).
//
// validUntilLedger is the expiration committed into the payload. It is the
// parameter, deliberately not whatever SignatureExpirationLedger the entry
// currently carries: the caller decides how long the signature lives, and the
// value written into the submitted credentials must match the value signed
// over, which AuthorizeEntry guarantees by setting both from this argument.
//
// networkPassphrase must be non-empty. An empty passphrase hashes to a
// perfectly valid-looking network id for a network that does not exist, so it
// is rejected rather than silently producing a signature no network accepts.
//
// The returned preimage shares no memory with entry, so later changes to entry
// cannot alter a payload that has already been derived.
func Preimage(entry xdr.SorobanAuthorizationEntry, validUntilLedger uint32, networkPassphrase string) (xdr.HashIdPreimage, error) {
	if networkPassphrase == "" {
		return xdr.HashIdPreimage{}, fmt.Errorf("soroauth: build preimage: network passphrase is empty")
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return xdr.HashIdPreimage{}, fmt.Errorf("soroauth: build preimage: %w", err)
	}

	networkID := xdr.Hash(network.ID(networkPassphrase))

	var preimage xdr.HashIdPreimage
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		preimage = xdr.HashIdPreimage{
			Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
			SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
				NetworkId:                 networkID,
				Nonce:                     credentials.Nonce,
				SignatureExpirationLedger: xdr.Uint32(validUntilLedger),
				Invocation:                entry.RootInvocation,
			},
		}

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		preimage = xdr.HashIdPreimage{
			Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress,
			SorobanAuthorizationWithAddress: &xdr.HashIdPreimageSorobanAuthorizationWithAddress{
				NetworkId:                 networkID,
				Nonce:                     credentials.Nonce,
				SignatureExpirationLedger: xdr.Uint32(validUntilLedger),
				Address:                   credentials.Address,
				Invocation:                entry.RootInvocation,
			},
		}

	default:
		// addressCredentials already rejected every arm that reaches here.
		return xdr.HashIdPreimage{}, fmt.Errorf("soroauth: build preimage: %w", ErrUnsupportedCredentials)
	}

	// The preimage above still points into the caller's entry through the
	// invocation tree and the address. Copying detaches it, so a caller that
	// mutates the entry afterwards cannot change a payload already derived.
	copied, err := xdrcopy.Copy(preimage)
	if err != nil {
		return xdr.HashIdPreimage{}, fmt.Errorf("soroauth: build preimage: %w", err)
	}
	return copied, nil
}

// Payload returns the 32 bytes a signer actually signs: the SHA-256 of the
// preimage's XDR encoding.
//
// This is split from Preimage so that a remote or hardware signer can be handed
// both the structure it is approving and the digest it must sign, rather than
// being asked to sign an opaque hash.
func Payload(p xdr.HashIdPreimage) ([32]byte, error) {
	encoded, err := p.MarshalBinary()
	if err != nil {
		return [32]byte{}, fmt.Errorf("soroauth: hash preimage: %w", err)
	}
	return sha256.Sum256(encoded), nil
}
