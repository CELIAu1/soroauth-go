# Glossary

The vocabulary this repository assumes. Terms are grouped by what they belong to
rather than alphabetised, because most of them only make sense next to the ones
they sit beside.

Where a term is defined by the protocol, the CAP is cited. Where a term is this
project's own, it says so — so nobody goes looking for `AuthorizeAll` in a CAP.

## The entry

**Authorization entry** (`SorobanAuthorizationEntry`) — what a transaction
carries so a contract's `require_auth()` can succeed for an address that is not
the transaction's source account. It has two halves: the **invocation tree**,
which is what is being approved, and the **credentials**, which is who approves
it and how. Defined in CAP-46-11.

**Invocation tree** (`rootInvocation`) — the call being authorized: a contract
address, a function name, its arguments, and recursively any sub-invocations
that call made. Approving the root approves the whole tree, which is why the
depth matters and why `Inspect` counts sub-invocations.

**Credentials** — the half that says who authorizes. Which **credential arm** is
in use decides what gets signed.

**Nonce** — a signed 64-bit integer in the credentials, one per entry, which the
host consumes so the same signed entry cannot be replayed. It is an `int64`, so
negative values are legal and this library's golden vectors include one
deliberately. Not a counter: there is no ordering requirement.

**Signature expiration ledger** — the last ledger at which the signature is
accepted. The host refuses when `current_ledger > signatureExpirationLedger`, so
the expiration ledger itself is still valid. The host also refuses a value above
its own `max_live_until_ledger`, a network setting this library cannot know
offline, which is why it caps nothing itself.

## The four credential arms

The arm decides which **preimage** is signed, and therefore what the signature
commits to.

**Source account** (`SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`) — no signature of its
own. The transaction's envelope signature authorizes it, so there is no address,
nonce or expiration. It still carries an invocation tree: the arm changes who
authorizes, not what.

**Address, or "legacy"** (`SOROBAN_CREDENTIALS_ADDRESS`) — an explicit address
signs, over a preimage that does **not** include that address. CAP-46-11. Not
deprecated: CAP-71-02 has a section titled "No deprecation of
`SOROBAN_CREDENTIALS_ADDRESS`" and says deprecation may be considered in
protocol 28 or later.

**Address V2** (`SOROBAN_CREDENTIALS_ADDRESS_V2`) — the same, except the signed
preimage includes the signer's address. CAP-71-02. That is the whole difference,
and it closes a narrow replay case: a key shared across accounts, plus a
contract that does not bind the address in its own arguments.

**Address with delegates** (`SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES`) — an
address plus a tree of **delegates**, all signing the same address-bound
preimage. CAP-71-01.

**Address-bound** — this project's shorthand for "the signed preimage includes
the signer's address", which is true of V2 and the delegates arm and false of
legacy.

## Signing

**Preimage** (`HashIdPreimage`) — the structure that is actually hashed and
signed. The signer never signs the entry: it signs
`SHA-256(XDR(HashIdPreimage))`. Which variant depends on the arm —
`ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` for legacy,
`ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` for V2 and delegates.

**Payload** — the 32 bytes that come out of that hash. What an ed25519 signature
is over, and what a hardware signer or passkey is shown. A signer that is given
only the payload is blind-signing; this library passes the preimage alongside it
so a remote signer can inspect what it is approving.

**Signature** — an `ScVal`, not a fixed structure. Its shape is whatever the
address's account logic expects. For a classic account the host expects a vector
of maps with `public_key` and `signature` keys, in that order; a custom account
defines its own, which is why `Verify` reports `cannot_check` for one rather
than a verdict.

## Delegates

**Delegate** — an address that signs on an account's behalf under CAP-71-01.
Every delegate, at every depth, signs the **same** payload as the top-level
address.

**Nested delegate** — a delegate with delegates of its own. Allowed to any
depth.

**Delegate ordering** — within one level, delegates must be in strictly
ascending order of the XDR encoding of their address. The host refuses a
mis-ordered or duplicated array before the account contract runs, so "strictly
ascending" also means "distinct". The same address at two _different_ levels is
allowed.

**Void top-level signature** — CAP-71-01 permits an account's own signature slot
to be `Void` when it authenticates purely through its delegates. So an entry
with nothing signed at the top can still be complete, which is why
`AuthorizeAll` does not treat an unsigned top-level node as an error.

## This project's own terms

Not protocol vocabulary. Nothing below appears in a CAP.**Credential node** —
any one place in an entry that can hold a signature: the top-level credentials,
or a delegate at any depth. "Signing an entry" usually means writing a signature
onto one or more nodes.

**Node path** — this project's term (used by `DiffEntries`), not protocol
vocabulary: a string locating a place inside an entry using the XDR field names,
such as `credentials.nonce`, `credentials.delegates[G…]` or
`rootInvocation.subInvocations[0].functionName`. Delegate nodes are keyed by
address rather than index, because an inserted delegate renumbers every node
after it and a renumbering would read as a change.

**Payload change** — this project's term: any difference between two entries
inside the signed preimage, so the two entries hash to different payloads and
every signature made against the first is invalid on the second. Output by
`DiffEntries` as `payload_changed`, with each individual `Change` carrying its
own `affects_payload` because whether a field moved the payload depends on the
credential arm.

**Stale signature** — this project's term, output by `DiffEntries` as
`stale_signatures`: a node that carries the same signature bytes in both entries
while `payload_changed` is true. It reads as signed and was never touched, but
the bytes commit to a payload the second entry no longer has, so the host
rejects it rather than the diff. Empty when a payload change came with fresh
signatures on every node — which is what a correct re-sign looks like.

**Verdict** — this project's term for the one-line judgment a report leads with,
such as an `EntryDiff`'s `summary`. Not to be confused with `Verify`'s
`cannot_check` outcome on custom account contracts, which is actually
`VerificationResult`, a distinct concept covered under the signing section
above.

**Target address** — the address whose node a signature is written to. By
default the signer's own; `ForAddress` names a different one. This library
writes a signature only onto a node whose address equals the target, which is a
deliberate difference from the JS SDK.

**Deterministic test key** — one of this project's own terms: an ed25519 key
whose seed is the SHA-256 digest of a fixed label, so `soroauth-vector-signer-1`
in a vector always expands to the same key. The determinism is the point:
vectors, fixtures and e2e scenarios regenerate identically on every machine and
there is nothing to check in. **These are public test keys — never fund one on
mainnet, and never import a real key as one.** The generator that produces them
is [`testdata/gen/gen.mjs`](../testdata/gen/gen.mjs).

**Golden vector** — a committed JSON file holding an entry, its preimage, its
payload and its signed result, generated by `@stellar/stellar-sdk` at an exact
pinned version. The correctness gate: CI regenerates them and fails on any
difference. Never edited by hand.

**Record pass and enforcing pass** — the two simulations a transaction needs
when an entry is signed by someone other than the transaction source. The record
pass reports which addresses must authorize and returns unsigned entries; the
enforcing pass re-simulates carrying the signed ones, so the resource fee
accounts for signature bytes the host has to read. Skipping the second produces
a transaction that is accepted, charged for, and then fails during application.

**Confidence** — not used here. It belongs to
[soroauth-explain](https://github.com/soroauth/soroauth-explain), which
describes what an entry authorizes. This library signs; it does not interpret.
