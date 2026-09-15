package soroauth

import "errors"

// The sentinel errors soroauth returns. Every one of them is matched with
// errors.Is, and every function that can produce one wraps it with
// fmt.Errorf("soroauth: <operation>: %w", err) so the message says what was
// being attempted while the sentinel stays comparable.
//
// These describe refusals, not failures. soroauth produces signatures that
// authorize value to move, so wherever the protocol or the caller's intent is
// ambiguous the library declines and returns one of these rather than guessing
// at what was meant.
var (
	// ErrSourceAccountCredentials is returned when a signing payload is
	// requested for an entry that uses SOROBAN_CREDENTIALS_SOURCE_ACCOUNT.
	//
	// That arm has no payload to sign: the transaction envelope's own
	// signature covers it, so there is no HashIdPreimage variant for it and
	// nothing for a Signer to do. It is an error from Preimage, but not from
	// AuthorizeEntry, which passes such entries through untouched so callers
	// can hand it every entry simulation returned.
	ErrSourceAccountCredentials = errors.New("credentials are source-account, which carry no signature payload")

	// ErrUnsupportedCredentials is returned for a credentials arm this
	// library does not know how to sign.
	//
	// The four defined arms are SOURCE_ACCOUNT (0), ADDRESS (1), ADDRESS_V2
	// (2) and ADDRESS_WITH_DELEGATES (3). A value outside that set means the
	// entry was built against a protocol this build does not implement, so
	// signing it would be a guess about a wire format that has not been read.
	ErrUnsupportedCredentials = errors.New("unsupported credentials type")

	// ErrNoMatchingCredentialNode is returned when no credential node in the
	// entry carries the address the signature was meant for.
	//
	// This is the fail-closed half of soroauth's target-address rule: a
	// signature is only ever written onto a node whose address equals the
	// target, so when nothing matches, the call fails instead of writing the
	// signature somewhere it does not belong. It is the error a caller sees
	// after signing with the wrong key, or naming an address via ForAddress
	// that is not in the delegate tree.
	ErrNoMatchingCredentialNode = errors.New("no credential node matches the target address")

	// ErrDuplicateDelegate is returned when one address appears twice within a
	// single delegates array.
	//
	// CAP-71-01 requires each delegates array to be sorted by address in
	// increasing order, which leaves no room for a repeat at the same level.
	// The same address at two different nesting levels is a different thing
	// and is allowed. The wrapped error names the offending address.
	ErrDuplicateDelegate = errors.New("duplicate delegate address at the same level")

	// ErrSignatureMismatch is returned when a signer's own signature fails to
	// verify against the payload it was just given.
	//
	// Ed25519Signer verifies its own output before handing it back. The cost
	// is one verification; what it catches is a corrupted key, a faulty
	// signer, or memory damage producing a signature that would be rejected
	// on-chain only after fees were paid.
	ErrSignatureMismatch = errors.New("signature does not verify against the payload")

	// ErrMissingSigner is returned by AuthorizeAll when an address-arm entry
	// has no signer for its address. The wrapped error names the address.
	//
	// AuthorizeAll never silently skips an entry: an unsigned address entry
	// means a transaction that is accepted, charged for, and then fails during
	// application. Refusing the whole batch is the cheaper failure.
	ErrMissingSigner = errors.New("no signer for address")

	// ErrAlreadySigned is returned when signing would overwrite or invalidate
	// a signature that is already present.
	//
	// Under CAP-71-01 every signature-bearing node in a delegates entry
	// commits to the same payload, and that payload includes the expiration
	// ledger, so re-signing one node with a different expiration silently
	// invalidates the signatures on all the others. It is also returned when
	// an entry that already carries a signature is converted to a different
	// credentials arm, because the payload type changes underneath the
	// existing signature. Pass AllowResign when overwriting is intended.
	ErrAlreadySigned = errors.New("credential node is already signed")

	// ErrInvalidExpiration is returned for an expiration ledger that cannot be
	// used: zero, an overflowing sum, or one that disagrees with the
	// expiration already committed to by existing signatures on the entry.
	//
	// Zero is rejected rather than treated as "no expiry" because the host
	// rejects an entry once the current ledger is past the stored value
	// (rs-soroban-env soroban-env-host/src/auth.rs, verify_and_consume_nonce:
	// `if ledger_seq > *live_until_ledger` → "signature has expired"), so a
	// zero expiration is not permissive, it is already expired.
	ErrInvalidExpiration = errors.New("invalid signature expiration ledger")

	// ErrTooManySignatures is returned when more signing keys are given for a
	// classic account than the host will accept.
	//
	// The host caps a classic account signature vector at MAX_ACCOUNT_SIGNATURES,
	// which is 20 (rs-soroban-env
	// soroban-env-host/src/builtin_contracts/account_contract.rs:25, enforced
	// at :185 with "too many account signers"). Exceeding it is rejected here
	// rather than on-chain.
	ErrTooManySignatures = errors.New("too many signatures for a classic account")
)
