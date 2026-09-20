# Issue backlog

Work that is worth doing and is not done. This file exists so the list can be
reviewed before the issues are created; the maintainer creates them, not a
contributor opening twenty at once.

Complexity is a rough guide to how much Soroban-specific knowledge an item
needs, not how long it takes.

- **trivial** — self-contained, no protocol knowledge required.
- **medium** — needs familiarity with the codebase or the auth flow.
- **high** — touches signing, the wire format, or cryptography. Needs a
  reference implementation to check against and a reviewer who knows the CAP.

Anything that changes the bytes soroauth emits must cite the CAP that requires
the change, and must come with a golden vector.

---

## Signers

### 1. secp256r1 / WebAuthn (passkey) signer

**Complexity:** high

Passkey wallets are the main reason a custom account contract exists in
practice, and soroauth currently makes their users write their own `SignerFunc`.
A first-class signer would produce the signature shape a passkey smart wallet's
`__check_auth` expects, including the authenticator data and client data JSON
that WebAuthn assertions carry.

**Acceptance criteria**

- A signer that takes a WebAuthn assertion and produces the `ScVal` a passkey
  wallet contract expects.
- At least one golden vector generated from an existing passkey wallet library,
  not written by hand, so the shape is checked against something real.
- Documentation stating which wallet contract the shape targets, since unlike
  the classic account signature there is no single host-defined format.
- An e2e scenario against a deployed passkey wallet contract, or an explicit
  note in the PR saying why that was not feasible.

### 2. `RequireAllSigned()` option for `AuthorizeAll`

**Complexity:** medium

`AuthorizeAll` returns a nil error for a delegates entry as long as one signer
matched somewhere in the tree, because it cannot know whether a given delegate's
signature was required — a 2-of-3 delegate policy is legitimate. That is the
right default, but a caller who *does* know every node must be filled currently
has to walk `Inspect` output themselves.

**Acceptance criteria**

- `RequireAllSigned()` option that fails with a sentinel error naming the first
  unsigned node when any credential node in any entry is left unsigned.
- Tests for the delegates arm with a partially signed tree, and for the
  single-node arms where the option is a no-op.
- The doc comment says what it does not cover: it cannot know whether an
  unsigned node was *allowed* to be unsigned, only that it is unsigned.

### 3. Remote signer example over HTTP

**Complexity:** medium

`SignerFunc` exists so signing can happen somewhere else, but there is no
worked example, and the interesting parts — sending the preimage so the remote
end can inspect what it is approving rather than blind-signing a digest, and
handling timeouts and cancellation — are exactly where people get it wrong.

**Acceptance criteria**

- A runnable example with a small HTTP signing service and a client
  `SignerFunc`.
- The preimage is transmitted, not just the payload hash, and the service
  decodes and logs what it is approving before signing.
- Context cancellation propagates to the HTTP request.
- A note on what the example deliberately does not do: no authentication, no
  key storage, not production-ready.

### 4. Hardware wallet signer notes

**Complexity:** medium

Ledger and similar devices sign a payload but need the structure to display it.
Document what a `SignerFunc` wrapping such a device has to do with the preimage,
and what those devices can and cannot currently show for Soroban auth entries.

**Acceptance criteria**

- A documentation page, not code, unless a device SDK makes a thin wrapper
  obviously correct.
- States plainly where the device cannot display the invocation, since a signer
  that cannot show what it signs is a meaningful limitation.

---

## Correctness and testing

### 5. Fuzz `ValidateDelegateOrder`

**Complexity:** medium

`ValidateDelegateOrder` walks attacker-supplied structure recursively. It should
never panic, and it should never accept an array that is out of order or
contains a duplicate within a level.

**Acceptance criteria**

- `FuzzValidateDelegateOrder` over arbitrary `SorobanAuthorizationEntry` bytes.
- Properties: never panics; every accepted entry has every delegates array
  strictly ascending by address XDR.
- A seed corpus from the golden vectors plus deliberately malformed trees.
- Deeply nested input is covered, since the recursion has no depth limit of its
  own beyond the XDR decoder's.

### 6. Fuzz `Inspect`

**Complexity:** medium

`Inspect` is the function most likely to be pointed at an untrusted entry —
that is what it is for — so it must never panic on one.

**Acceptance criteria**

- `FuzzInspect` over arbitrary entry bytes.
- Properties: never panics; every entry that decodes either produces an
  `EntryInfo` or an error, never a partially populated struct alongside an
  error.
- Seeds from the golden vectors and from entries with empty union arms.

### 7. Cross-check the vectors against the Python SDK

**Complexity:** medium

The vectors prove soroauth agrees with `@stellar/stellar-sdk`. They do not rule
out a bug that both implementations share. A third independent implementation
would.

**Acceptance criteria**

- A script that reads `testdata/vectors/*.json` and recomputes the preimage and
  payload with the Python `stellar-sdk`.
- Any disagreement is investigated and reported, not silently accommodated.
- Run in CI if the Python SDK supports every arm, including delegates; if it
  does not, the script says which cases it skipped and why.

### 8. Benchmarks

**Complexity:** trivial

No performance claims are made anywhere, and none should be made without
measurements. A backend signing many entries per transaction may care.

**Acceptance criteria**

- Benchmarks for `Preimage`, `Payload`, `AuthorizeEntry` on all three arms, and
  `AuthorizeAll` over a realistic batch.
- A benchmark for a deep delegate tree, since that path is recursive and
  deep-copies.
- Results recorded in the PR, with the machine they came from.

### 9. Property test: signed and stored expiration never disagree

**Complexity:** medium

The single most dangerous failure this library could have is emitting an entry
whose stored `signatureExpirationLedger` differs from the one that was signed
over. It looks complete and fails on-chain. Several tests check it incidentally;
none asserts it as a property.

**Acceptance criteria**

- A property test over generated entries and expirations: for every entry
  `AuthorizeEntry` returns, rebuilding the preimage from that entry reproduces
  the payload its signature verifies against.
- Covers all three address arms and delegate trees at several depths.

---

## API

### 10. `Inspect` on a full `TransactionEnvelope`

**Complexity:** medium

Callers usually hold an envelope, not a loose entry, and currently have to dig
the `InvokeHostFunction` operation out themselves before they can inspect
anything.

**Acceptance criteria**

- `InspectEnvelope` accepting a `TransactionEnvelope` and returning one
  `EntryInfo` per authorization entry, with the operation index.
- Handles fee-bump envelopes by inspecting the inner transaction.
- An envelope with no `InvokeHostFunction` operation is an error, not an empty
  result.
- The CLI's `inspect` accepts an envelope as well as an entry, detecting which
  it was given.

### 11. `AuthorizeAll` should accept a delegate plan

**Complexity:** medium

To use the delegates arm through `AuthorizeAll` today you must wrap each entry
with `WithDelegates` yourself first, which means unpacking the batch, matching
entries to accounts, and repacking. The batch helper stops helping at exactly
the point the work gets fiddly.

**Acceptance criteria**

- An option letting the caller supply, per address, the delegate tree to wrap
  that entry with before signing.
- Entries whose address has no plan are signed as they are.
- An address in the plan that appears in no entry is an error, matching
  `ForAddress`'s behaviour — never a silent no-op.

### 12. Nested delegates in the CLI

**Complexity:** medium

`soroauth delegates` takes a flat list. Nesting is library-only, which `--help`
says, but it makes the CLI unable to express a tree the library handles fine.

**Acceptance criteria**

- A syntax for nesting — a repeated `--nested PARENT=CHILD`, or a JSON tree on
  stdin. Pick one and document why.
- Round-trips: a tree built through the CLI matches one built through
  `WithDelegates`.
- Golden-vector coverage for whatever syntax is chosen.

### 13. Go doc examples for every exported function

**Complexity:** trivial

`go doc` currently shows signatures and prose but no runnable examples, and
`Example` functions are compiled and run by `go test`, so they cannot rot.

**Acceptance criteria**

- An `Example` for every exported function and type.
- Examples use deterministic keys and fixed nonces so their output is stable.
- They appear on pkg.go.dev and pass under `go test`.

### 14. Typed errors carrying the offending address

**Complexity:** trivial

`ErrNoMatchingCredentialNode`, `ErrDuplicateDelegate` and `ErrMissingSigner` all
name an address in their message, but a caller wanting to act on it has to parse
the string.

**Acceptance criteria**

- Error types carrying the address as a field, wrapping the existing sentinels
  so `errors.Is` keeps working.
- `errors.As` recovers the address.
- Message text is unchanged.

---

## Documentation

### 15. CAP-85 note once the Go SDK has Protocol 28 helpers

**Complexity:** medium

Protocol 28 is live on testnet. When the Go SDK gains helpers for its new
features, the documentation should say what they mean for authorization entries
and whether anything in soroauth needs to change.

**Acceptance criteria**

- Read CAP-85 and the Go SDK release notes; do not write from memory.
- A documentation section stating what changes for auth entries, and explicitly
  stating "nothing changes for this library" if that is the answer.
- If the wire format is affected, a golden vector and an e2e scenario.

### 16. A worked multi-party signing guide

**Complexity:** medium

The hard part of the delegates arm is operational, not API-shaped: who signs
first, what gets passed between parties, and why the expiration cannot change
once anyone has signed. That last rule is enforced in code and explained in a
doc comment, but there is no guide showing the flow.

**Acceptance criteria**

- A guide walking through a delegate tree signed by three parties in sequence.
- Shows what each party receives and returns, using the CLI so it is
  copy-pasteable.
- Explains the expiration rule at the point it would bite.

### 17. Document the simulation two-pass requirement

**Complexity:** trivial

CAP-71-01 needs record, then sign, then enforce. The e2e tests do it and
`e2e/README.md` explains it, but a library user reading only the main README
could reasonably skip the second pass and be confused by fee errors.

**Acceptance criteria**

- A README section on the two-pass flow and what goes wrong without it.
- Notes that the Go SDK has no `assembleTransaction`, and shows the explicit
  assembly.

---

## Tooling

### 18. `soroauth verify`

**Complexity:** medium

There is no way to check that an entry's signatures actually verify without
submitting it. For a classic account signature the library has everything it
needs to check locally.

**Acceptance criteria**

- Verifies every classic-account signature in an entry against the payload the
  entry itself commits to, given the network and expiration.
- Reports per node: verified, unsigned, or a shape it cannot check.
- Says plainly that a custom account signature cannot be verified offline, since
  only the contract knows what valid means.

### 19. CLI reads entries from stdin

**Complexity:** trivial

Every subcommand takes `--entry` as a base64 argument, which is awkward for
large entries and for pipelines.

**Acceptance criteria**

- `--entry -` reads from stdin.
- Piping `soroauth delegates` into `soroauth sign` works without a shell
  variable.
- `--help` shows the piped form.

### 20. Publish the CLI as a container image

**Complexity:** trivial

CI systems that need to sign an entry should not have to install a Go toolchain.

**Acceptance criteria**

- A minimal image built from a release tag.
- Documented usage passing a seed through an environment variable, consistent
  with `--secret-env`, with a note that the variable is visible to anything
  inspecting the container.

### 21. Release automation

**Complexity:** trivial

v0.1.0 was tagged by hand.

**Acceptance criteria**

- A workflow that runs on a tag, builds CLI binaries for the usual platforms,
  and attaches them to a GitHub release.
- Release notes come from `CHANGELOG.md` rather than being retyped.
- The workflow refuses to release if the golden-vector drift check fails.
