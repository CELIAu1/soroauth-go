package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// UpgradeToV2 converts an unsigned SOROBAN_CREDENTIALS_ADDRESS entry into the
// equivalent SOROBAN_CREDENTIALS_ADDRESS_V2 entry, leaving the input untouched.
//
// Why a caller needs this: simulation may hand back either arm. The RPC request
// field that asks for V2, SimulateTransactionRequest.UseUpgradedAuth in
// go-stellar-sdk's protocols/rpc package, is explicitly best-effort — its own
// documentation says it affects only the recording auth modes and is silently
// ignored by protocol versions whose host cannot emit AddressV2
// (protocols/rpc/simulate_transaction.go:24-32). That field is also described
// there as transitional, to become a no-op once the RPC returns AddressV2 by
// default, so callers should not rely on omitting it to keep receiving the
// legacy format either. A caller who requires V2 must therefore check what came
// back, and upgrade it if necessary, rather than assume.
//
// What changes: only the credentials arm. The address, nonce, expiration and
// invocation are carried over unchanged. What that changes is the signing
// payload, which becomes address-bound under
// ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS (CAP-71-01) instead of the
// legacy ENVELOPE_TYPE_SOROBAN_AUTHORIZATION.
//
// Because the payload changes, an entry that already carries a signature cannot
// be upgraded: that signature would no longer verify, and the resulting entry
// would look complete while being rejected on-chain. Such an entry returns
// ErrAlreadySigned. The ScvVoid and empty-ScvVec placeholders that simulation
// emits are not signatures and are upgraded normally.
//
// An entry that is already V2 is returned as an unaliased copy with a nil
// error, so callers can upgrade unconditionally. Every other arm, including
// source-account and the delegates arm, returns ErrUnsupportedCredentials.
func UpgradeToV2(entry xdr.SorobanAuthorizationEntry) (xdr.SorobanAuthorizationEntry, error) {
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		copied, err := xdrcopy.Copy(entry)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: upgrade to v2: %w", err)
		}
		return copied, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if entry.Credentials.Address == nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
				"soroauth: upgrade to v2: address credentials arm is empty")
		}
		if isSigned(entry.Credentials.Address.Signature) {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
				"soroauth: upgrade to v2: the upgrade changes the signing payload, invalidating the existing signature: %w",
				ErrAlreadySigned)
		}

		upgraded, err := xdrcopy.Copy(entry)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: upgrade to v2: %w", err)
		}
		// The copy owns its credentials, so the arm can be moved across
		// without touching the caller's entry.
		credentials := upgraded.Credentials.Address
		upgraded.Credentials = xdr.SorobanCredentials{
			Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: credentials,
		}
		return upgraded, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: upgrade to v2: source-account credentials have no address arm to upgrade: %w",
			ErrUnsupportedCredentials)

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: upgrade to v2: the delegates arm is already address-bound: %w",
			ErrUnsupportedCredentials)

	default:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: upgrade to v2: %w", ErrUnsupportedCredentials)
	}
}
