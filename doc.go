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
// The package example shows that path end to end: DecodeAuthorizationEntry on
// an entry from simulateTransaction, UpgradeToV2 when simulation returned the
// legacy arm, ExpirationAfter on the ledger simulation reported,
// AuthorizeEntry to sign, and the base64 encoding that goes back into the
// transaction. Real submissions need a second, enforce-mode simulation after
// signing; the README's "The two-pass simulation requirement" section explains
// why.
//
// # Exported constants
//
// The following constants are the values a caller switches on. They are grouped
// by the type or decision each belongs to. Strings marked "stable" are safe to
// persist in config, logs, or databases; strings not marked stable are
// implementation details that may change between versions.
//
// Credential type names (stable — Inspect and the CLI report these)
//
//	CredentialTypeSourceAccount        = "source_account"
//	CredentialTypeAddress              = "address"
//	CredentialTypeAddressV2            = "address_v2"
//	CredentialTypeAddressWithDelegates = "address_with_delegates"
//
// Credential arms (stable — same values as the credential type names)
//
//	ArmSourceAccount        = "source_account"
//	ArmAddress              = "address"
//	ArmAddressV2            = "address_v2"
//	ArmAddressWithDelegates = "address_with_delegates"
//
// Decode limits (numeric constants, stable)
//
//	MaxDecodeDepth       = 64
//	MaxDecodeInputBytes  = 1 << 20 (1 MiB decoded)
//
// Signature shapes (stable — DescribeSignature returns these)
//
//	SignatureShapePasskey  = "passkey"
//	SignatureShapeMap      = "map"
//	SignatureShapeUnknown  = "unknown"
//
// Verification verdicts (stable — VerifyEntry and CheckPossession return these)
//
//	VerdictVerified      = "verified"
//	VerdictUnsigned      = "unsigned"
//	VerdictInvalid       = "invalid"
//	VerdictCannotCheck   = "cannot_check"
//
// Error sentinels (stable — every function that can fail wraps one of these)
//
//	ErrSourceAccountCredentials
//	ErrUnsupportedCredentials
//	ErrNoMatchingCredentialNode
//	ErrDuplicateDelegate
//	ErrSignatureMismatch
//	ErrMissingSigner
//	ErrAlreadySigned
//	ErrInvalidExpiration
//	ErrTooManySignatures
//	ErrDecodeLimit
//	ErrNoInvokeOperation
//	ErrUnsupportedEnvelope
//	ErrUnsignedCredentialNode
//	ErrDelegatePlanUnmatched
//	ErrNonceAlreadyReserved
//	ErrWebAuthnMalformedJSON
//	ErrWebAuthnMissingField
//	ErrWebAuthnMalformedField
//	ErrWebAuthnTruncatedAuthenticatorData
//	ErrWebAuthnChallengeMismatch
//	ErrSignerAddressMismatch
//	ErrVaultUnauthorized
//	ErrVaultKeyNotFound
//	ErrVaultKeyType
//	ErrLedgerUnavailable
//	ErrLedgerLocked
//	ErrLedgerWrongApp
//	ErrLedgerBlindSigningDisabled
//	ErrLedgerDenied
//	ErrAttestationMalformed
//	ErrAttestationInvalid
//	ErrAttestationUnsupportedFormat
//	ErrPolicyRefusal
//	ErrSignerTransient
//	ErrChainExhausted
//	ErrQuorumNotMet
//	ErrQuorumDisagreement
//
// Chain outcomes (stable — signer chain audit records use these)
//
//	ChainSucceeded          = "succeeded"
//	ChainTransientFailure   = "transient_failure"
//	ChainTerminalFailure    = "terminal_failure"
//	ChainSkipped            = "skipped"
//
// Diff change kinds (stable — DiffEntries reports these)
//
//	ChangeKindArm              = "arm"
//	ChangeKindAddress          = "address"
//	ChangeKindNonce            = "nonce"
//	ChangeKindExpiration       = "expiration"
//	ChangeKindInvocation       = "invocation"
//	ChangeKindDelegateAdded    = "delegate_added"
//	ChangeKindDelegateRemoved  = "delegate_removed"
//	ChangeKindSignature        = "signature"
//
// Attestation formats (stable — WebAuthn §8)
//
//	AttestationFormatNone  = "none"
//	AttestationFormatPacked = "packed"
//
// Attestation trust levels (stable — VerifyAttestation returns these)
//
//	AttestationTrustNone    = "none"
//	AttestationTrustSelf    = "self"
//	AttestationTrustUnrooted = "unrooted"
//	AttestationTrustRooted   = "rooted"
//
// Hook phases (stable — Hook.Event receives these)
//
//	HookPhasePreimage = "preimage"
//	HookPhaseSign     = "sign"
//	HookPhasePostSign = "post_sign"
//	HookPhaseWrite    = "write"
//
// Signer capabilities (bitmask, stable numeric values)
//
//	CapabilityDeterministic    = 1
//	CapabilityInteractive      = 2
//	CapabilityRemote           = 4
//	CapabilityBatchedPresence  = 8
//
// Finding severities (stable — Analyze reports these)
//
//	SeverityInfo     = "info"
//	SeverityWarning  = "warning"
//	SeverityCritical = "critical"
//
// Protocol versions (ArmProtocolVersion map — values from CAP preambles, stable)
//
//	CredentialTypeSourceAccount        → 20 (CAP-46-11)
//	CredentialTypeAddress              → 20 (CAP-46-11)
//	CredentialTypeAddressV2            → 27 (CAP-71-01)
//	CredentialTypeAddressWithDelegates → 27 (CAP-71-01)
//
// P-256 key sizes (numeric constants, stable)
//
//	Secp256r1PublicKeySize  = 65 (uncompressed SEC1)
//	Secp256r1SignatureSize  = 64 (fixed-width r || s)
//
// Classic account signature limit (numeric constant, stable — host-enforced)
//
//	maxAccountSignatures = 20 (not exported; ErrTooManySignatures is the exported sentinel)
//
// Internal constants (not stable — do not persist)
//
//	possessionNetworkPassphrase = "soroauth possession check - this is not a network"
//	possessionFunction          = "soroauth_possession_check"
//
// Status: v0.1.0, unaudited.
package soroauth
