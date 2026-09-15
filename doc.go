// Package soroauth builds, signs, and inspects Soroban authorization entries.
//
// When a Soroban contract calls require_auth() on an address that is not the
// transaction's source account, the transaction must carry a
// xdr.SorobanAuthorizationEntry for that address. The entry has two parts:
// rootInvocation, the call tree being approved, and credentials, which say who
// approves it and carry a nonce, a signature expiration ledger, and a
// signature whose shape the address's account logic defines.
//
// A signer never signs the entry directly. It signs
// SHA-256(XDR(HashIdPreimage)), where the preimage variant depends on the
// credential arm:
//
//	credential arm                            value  preimage variant                              address signed?
//	----------------------------------------  -----  --------------------------------------------  ---------------
//	SOROBAN_CREDENTIALS_SOURCE_ACCOUNT            0   none (the tx envelope covers it)              n/a
//	SOROBAN_CREDENTIALS_ADDRESS (legacy)          1   ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9)       no
//	SOROBAN_CREDENTIALS_ADDRESS_V2                2   ..._SOROBAN_AUTHORIZATION_WITH_ADDRESS (10)   yes
//	SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES    3   ..._SOROBAN_AUTHORIZATION_WITH_ADDRESS (10)   yes
//
// The legacy arm is defined by CAP-46-11. The V2 and delegated-signer arms are
// defined by CAP-71-01 and CAP-71-02. V2 binds the signer's address into the
// signed payload, which closes a narrow replay case: a key shared across
// several accounts, combined with a contract that does not itself bind the
// address into its arguments.
//
// For the delegated-signer arm the payload is bound to the top-level address,
// and the top-level account together with every delegate at every nesting
// depth signs that same payload (CAP-71-01).
//
// Scope: soroauth turns an unsigned entry, usually one returned by
// simulateTransaction, into a correctly signed one. It is not a transaction
// builder, an RPC client, or a key manager; it consumes go-stellar-sdk's
// txnbuild and clients/rpcclient rather than wrapping them, and signers are an
// interface of which only an in-memory ed25519 implementation ships.
//
// Status: v0.1.0, unaudited.
package soroauth
