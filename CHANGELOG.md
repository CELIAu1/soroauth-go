# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (docs correctness)

- The README's three Go examples (Quickstart, Delegates, the inline
  `AllowResign` snippet) are now extracted verbatim, at test time, from real,
  compiling source in `internal/readmesnippets/`, instead of living only as
  free-standing markdown text nothing checked. `TestReadmeSnippetsMatchTheirSource`
  fails and names the snippet if the README drifts from its source; the
  source itself is compiled by the `go build ./...` / `go vet ./...` CI
  already runs, since it carries no build tag, so a snippet that stops
  compiling fails the same way any other compile error does. See
  CONTRIBUTING.md § Verifying README snippets compile. In the course of this,
  the Quickstart and Delegates examples gained the error checks they were
  previously missing (three unchecked errors in Quickstart; the Delegates
  loop swallowed its error entirely, which would not even have compiled once
  wrapped in a real function — `declared and not used: err`).

### Security

- CI: every GitHub Action is now pinned to a full commit SHA (with the
  version recorded in a trailing comment), replacing mutable tags like
  `@v7`. A retagged or compromised action can no longer silently gain this
  repository's CI permissions. `.github/dependabot.yml` keeps the pins
  current by opening a PR that updates the SHA and its comment together.

### Added

**`soroauth doctor`**

- New CLI subcommand checking the local environment for the failures that are
  usually the real cause of a confusing `sign` or `payload` error: an old Go
  toolchain, an unreachable RPC endpoint, or a mistyped `--secret-env`
  variable name. Reports each check as pass/fail, with `--json` for
  structured output, and never prints a secret's value — only whether it is
  set. Exit code reflects overall status (0 all passed, 1 something failed).

**Scoped `AllowResign`**

- `AllowResign` now accepts optional addresses:
  `AllowResign(addresses ...string)`. With no arguments it behaves exactly as
  before — the guard is lifted for whatever address the call targets. With one
  or more addresses, the guard is lifted only when the call's target
  (`ForAddress`, or the signer's own `Address()`) is among them; a target that
  is not named still refuses with `ErrAlreadySigned`, even though
  `AllowResign` was passed. This lets a caller replacing one delegate's
  signature grant the override to just that address, instead of every
  already-signed node an `AuthorizeEntry` call in the same batch might touch.
  The delegates arm's expiration guard (§5.4) is unaffected either way: no
  address list can lift it.

  **Migration:** none required. `AllowResign()` with no arguments is
  unchanged, so every existing call site keeps its current behaviour. No
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Typed address errors**

- `NoMatchingCredentialNodeError`, `DuplicateDelegateError` and
  `MissingSignerError`: error types that wrap the existing
  `ErrNoMatchingCredentialNode`, `ErrDuplicateDelegate` and `ErrMissingSigner`
  sentinels and expose the offending address as an `Address` field.
  `errors.Is` keeps matching the sentinels unchanged, and `errors.As`
  recovers the address without parsing the error string:

  ```go
  var addrErr *soroauth.MissingSignerError
  if errors.Is(err, soroauth.ErrMissingSigner) && errors.As(err, &addrErr) {
      log.Printf("no signer for %s", addrErr.Address)
  }
  ```

  **Migration:** none required. Error messages are byte-identical to v0.1.0,
  and every existing `errors.Is(err, Err…)` check continues to work. Callers
  that previously extracted an address by substring-matching the message may
  switch to `errors.As`; that is optional. No emitted signature or entry bytes
  change, so golden vectors are unaffected.

- Go doc examples for each of the three typed errors, showing the
  `errors.Is` + `errors.As` recovery pattern.
- Signing-path benchmarks covering `Preimage`, `Payload`, `AuthorizeEntry` on
  all three arms (legacy, V2, flat delegates, depth-8 delegate chain),
  `AuthorizeAll` over a 12-entry realistic batch, and
  `AuthorizeInvocation`. CI gates allocs/op and B/op against
  `testdata/bench/budgets.json` via `scripts/checkbench`; `ns/op` is reported
  in PRs but never fails the build. See CONTRIBUTING.md § Benchmarks.

## [0.1.0] — 2026-09-16

First release. Unaudited.

### Added

**Signing payloads**

- `Preimage` builds the `HashIdPreimage` for an entry, choosing the variant from
  the credentials arm: `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` for legacy
  `SOROBAN_CREDENTIALS_ADDRESS` (CAP-46-11), and
  `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` for both
  `SOROBAN_CREDENTIALS_ADDRESS_V2` and
  `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-71-01).
- `Payload` returns the 32 bytes a signer signs.

**Signers**

- `Signer` interface, receiving both the preimage and its payload hash so a
  remote or hardware signer can inspect what it is approving.
- `NewEd25519Signer` for a classic account with one key. It verifies its own
  signature before returning it.
- `NewAccountMultiSigner` for a classic account with several keys, sorted
  strictly ascending by raw public key and capped at 20, as the host requires.
  No JS SDK equivalent.
- `SignerFunc` for custom account contracts whose signature shape the caller
  owns.

**Authorizing**

- `AuthorizeEntry` with `ForAddress` and `AllowResign`.
- `AuthorizeInvocation` for building and signing an entry from scratch,
  defaulting to the V2 arm.
- `AuthorizeAll` for signing a batch, all or nothing.
- `UpgradeToV2` for converting an unsigned legacy entry.

**Delegates (CAP-71-01)**

- `Delegate`, `WithDelegates` and `ValidateDelegateOrder`, supporting arbitrarily
  nested trees, sorting every level by the XDR encoding of the address and
  rejecting duplicates within a level.

**Everything else**

- `Inspect` reporting an entry's structure, `ExpirationAfter`, `ParseAddress`
  and `FormatAddress`.
- Nine exported sentinel errors, each with a test that produces it.
- `soroauth` CLI with `payload`, `sign`, `delegates` and `inspect`. Secrets are
  read only from a named environment variable, never a flag value.

### Proven

- Nine golden vectors generated by `@stellar/stellar-sdk@17.1.0` assert that the
  preimage, payload hash and final signed entry are byte-identical to the
  reference, across both networks, legacy and V2 arms, sub-invocation and
  create-contract trees, the int64 nonce edges, and three delegate cases
  including one address at two nesting depths. The delegate vectors reproduce
  `WithDelegates` itself from the recorded unsorted input rather than re-reading
  an entry the reference already built. CI regenerates them on every push and
  fails on drift.
- Six scenarios on Stellar testnet, protocol version 28, covering all three
  address arms plus multisig, and two rejection scenarios that assert the host's
  specific reason. Transaction hashes in [e2e/RESULTS.md](e2e/RESULTS.md).

### Known limitations

- Unaudited.
- The CLI's `delegates` subcommand takes a flat list; nested delegates are
  library-only.
- No secp256r1 / WebAuthn signer. See `docs/ISSUE_BACKLOG.md`.
- `AuthorizeAll` does not require every delegate node to be signed, because it
  cannot know an account's delegation policy. Check `Inspect`'s per-node
  `Signed` flags before submitting.

[0.1.0]: https://github.com/soroauth/soroauth-go/releases/tag/v0.1.0
