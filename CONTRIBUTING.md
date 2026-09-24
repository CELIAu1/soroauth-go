# Contributing

Thanks for looking. This library produces signatures that move money, so the bar
for changes is higher than the size of the codebase suggests. Most of what
follows exists to keep the evidence honest rather than to police style.

## Setup

```sh
git clone https://github.com/soroauth/soroauth-go
cd soroauth-go
go test ./...
```

That is the whole setup for the library and CLI. Go 1.25.0 or later.

Two optional pieces need more:

- **Regenerating golden vectors** needs Node (>= 22.12.0, what
  `@stellar/stellar-sdk@17.1.0` declares).
- **Running the e2e tests** needs Rust 1.93.0 (pinned in
  `e2e/contracts/rust-toolchain.toml`, rustup will fetch it) and
  `stellar-cli` 28.0.0.

## Before you open a pull request

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

CI runs exactly these, plus the golden-vector drift check and the signing-path
budget check (see [Benchmarks](#benchmarks)).

## Benchmarks

The signing path has committed benchmarks in `bench_signing_test.go` covering
`Preimage`, `Payload`, `AuthorizeEntry` on all three arms (legacy, V2,
delegates, including a depth-8 delegate chain), and `AuthorizeAll` over a
12-entry, 4-signer batch.

```sh
# Full suite with allocation stats
go test -run '^$' -bench . -benchmem -count=1 .

# One arm
go test -run '^$' -bench 'BenchmarkAuthorizeEntry/delegates' -benchmem .
```

CI runs the same command and gates on **allocs/op and B/op** only, via:

```sh
go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out
go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json
```

`ns/op` is reported for humans in PRs (with the machine it came from) but never
fails the build: wall-clock on a shared runner is noise. Allocation counts are
deterministic for a given Go version and are the regression signal.

`testdata/bench/budgets.json` is the committed baseline. It carries ~40%
headroom over the measured values so a Go minor bump does not flake CI. If the
checker fails:

- If the increase is a bug, fix the bug; do not raise the budget.
- If the increase is intentional, raise the budget in the **same commit** as
  the change and say in the commit body which function got more expensive and
  why that is acceptable.
- Never lower a budget without a fresh local measurement on the machine named
  in the commit body.

When you add a benchmark, add a budget in the same commit. The checker prints
`WARN … no budget` for any benchmark it sees without one, and
`FAIL … benchmark not found` if a budgeted name is missing from the output —
so a renamed benchmark cannot silently drop out of the gate.

## Verifying README snippets compile

The README's two Go examples (Quickstart, Delegates) are not free-standing
markdown text: each is extracted verbatim from a real, compiling source file
in `internal/readmesnippets/`, between a `// snippet:start <name>` and
`// snippet:end <name>` comment pair. `TestReadmeSnippetsMatchTheirSource` in
`readme_test.go` at the repository root asserts the fenced code block in
README.md is byte-identical (modulo tabs-vs-spaces) to that marked region.

This means two different things can fail, and the test names which:

- **The snippet source stops compiling.** It is an ordinary package with no
  build tag, so `go build ./...` and `go vet ./...` — which CI already runs
  on every push — catch this like any other compile error, naming the file
  and line.
- **The README drifts from its source**, for example a hand-edit to the
  fenced block without updating `internal/readmesnippets/`, or the reverse.
  `TestReadmeSnippetsMatchTheirSource` fails and prints both texts.

To reproduce either failure locally:

```sh
go build ./...                        # catches a snippet that no longer compiles
go test -run TestReadmeSnippets -v .  # catches README/source drift, naming the snippet
```

To change an example, edit the marked region in
`internal/readmesnippets/*.go` and copy it verbatim (as, or converted from,
tabs) into the matching fenced block in README.md. Never edit the fenced
block alone: it is not the source of truth, and the drift test will fail on
the next run.

## GitHub Actions are pinned to commit SHAs

Every `uses:` in `.github/workflows/*.yml` names a full commit SHA with the
version in a trailing comment, e.g. `actions/checkout@3d3c42e… # v7`, never a
mutable tag like `@v7`. A major-version tag can be retagged to point at a
different commit; pinning to the SHA means a compromised or retagged action
cannot silently start running with this repository's CI permissions.

Dependabot (`.github/dependabot.yml`) watches the `github-actions` ecosystem
and opens a PR updating both the SHA and its version comment together when a
new release comes out, so the two can never drift apart. To pin a new action
by hand, resolve the tag to a commit first:

```sh
git ls-remote --tags https://github.com/<owner>/<repo> | grep 'refs/tags/v7$'
```

Use the first column's SHA (for an *annotated* tag, `git ls-remote` also
prints a `refs/tags/v7^{}` line — use that dereferenced commit SHA, not the
tag object's own SHA).

## Golden vectors

`testdata/vectors/*.json` are generated, committed artefacts. They are the
evidence that soroauth agrees byte-for-byte with the reference implementation.

**Never edit a vector by hand.** Not to fix a failing test, not to adjust a
field, not for anything. A hand-edited vector is a test that has been made to
agree with the code instead of the other way round, which is precisely the
failure the vectors exist to prevent. CI regenerates them on every push and
fails if the committed files differ, so an edit will be caught — but the reason
not to do it is that it destroys the evidence, not that you will be caught.

To change them, change the generator:

```sh
cd testdata/gen
npm ci
node gen.mjs
```

Then commit the regenerated files together with the generator change.

If a vector disagrees with the Go code, the Go code is wrong until proven
otherwise. If you believe the vector itself is wrong, stop and open an issue
saying why, with the protocol reference — do not change it to make a test pass.

The generator refuses to run against any `@stellar/stellar-sdk` other than the
pinned 17.1.0, since a vector from another build is not evidence about this one.

## Running the e2e tests

```sh
cd e2e/contracts && stellar contract build
cd ../.. && go test -tags e2e -v ./e2e/...
```

They run against testnet by default; `SOROAUTH_RPC_URL` points them elsewhere.
Accounts are generated at runtime and funded by friendbot. A full run takes
about three minutes.

`e2e/RESULTS.md` is written by a run and only when every scenario ran. Commit it
only from a real, complete run — it is what the README's testnet claims point
at.

See [e2e/README.md](e2e/README.md) for what each scenario proves and why the two
rejection scenarios exist.

## Property-based tests

The address package includes property-based tests using [gopter](https://github.com/leanovate/gopter).
These tests generate thousands of random G... and C... addresses and verify:

- ParseAddress/FormatAddress round-trips for both address types
- XDR encoding stability across round-trips
- Rejection of invalid inputs (muxed addresses, secret seeds, liquidity pools,
  claimable balances, malformed base32, corrupted checksums, truncated addresses,
  empty strings)

### Running property tests locally

```sh
# Run the full property test suite (1000 iterations per property)
go test -run TestParseAddressFormatAddressProperty -v ./...

# Run the deterministic subset (100 iterations, fixed seed for CI reproducibility)
go test -run TestParseAddressFormatAddressDeterministic -v ./...

# Run the complementary XDR-level tests
go test -run 'TestParseAddressWithRandomXDR|TestFormatAddressRejectsInvalidXDR' -v ./...
```

### Reproducing a property test failure

If a property test fails, the output will show the seed and the generated value
that caused the failure. To reproduce:

```sh
# 1. Note the seed from the failure output (e.g., "failed with initial seed: 12345")
# 2. Run with that seed:
go test -run TestParseAddressFormatAddressProperty -v -count=1 ./... 2>&1 | head -50

# Or run the deterministic test which uses a fixed seed:
go test -run TestParseAddressFormatAddressDeterministic -v ./...
```

The deterministic test (`TestParseAddressFormatAddressDeterministic`) runs a
fixed set of 100 iterations per property with seed `0xDEADBEEF` and is the one
executed in CI. If it passes locally but the full property test fails, the
failure is in the extended search space — increase `MinSuccessfulTests` in the
deterministic test to narrow it down.

### Capturing regressions

If a property test discovers a bug, capture the failing input as a regression
fixture in `address_test.go` by adding a new table entry to
`TestParseAddressRejects` or `TestParseAddressFormatAddressRoundTrip` with the
exact address string that triggered the failure. This ensures the specific
case remains covered even if the property test parameters change.

## What a change needs

- **Tests that can fail.** A test that passes for the wrong reason is worse than
  no test, because it reads as evidence. Two of this repo's own tests were
  originally written that way and had to be fixed: a rejection scenario that
  asserted only "the transaction failed" was passing while the transaction ran
  out of instructions and never reached the check it was supposedly about. If
  you add a test that expects a failure, assert *which* failure.
- **A test that proves the guard bites.** Where practical, break the thing
  deliberately, confirm the test fails, and say so in the commit message. Do not
  commit the break.
- **No mutation of caller input.** Every function returning a modified entry
  deep-copies first and has a test proving the input's bytes are unchanged.
- **Errors that name the sentinel.** Wrap with
  `fmt.Errorf("soroauth: <operation>: %w", err)` and match with `errors.Is`.
- **Context is checked and passed down, never dropped.** Every exported
  function that takes a `context.Context` as its first parameter must check
  `ctx.Err()` before doing work — so a cancelled context fails closed even on
  a path that never reaches a signer (a source-account entry, an empty
  batch) — and must pass that same context, unchanged, to every call that can
  block or produce a signature, in particular `Signer.Sign`. Every such
  function has a cancellation test that asserts `context.Canceled` and that
  the signer was not invoked; add one for any new context-taking function.
- **Fail closed.** Where the protocol or the caller's intent is ambiguous,
  refuse and return an error rather than guess. Say which reading you chose in
  the commit message.
- **Cited protocol claims.** Any statement about host behaviour in a doc
  comment, README or commit message needs a source — the CAP, the
  `rs-soroban-env` file and function, or the SDK file and line. Not memory.

## Commit format

Conventional commits, lowercase and imperative:

```
feat(authorize): sign delegate nodes by address
test(golden): cover delegate vectors
docs(readme): write readme
ci: add golden drift job
```

One logical unit per commit — a function and its tests, one CLI subcommand, one
document. Commit bodies carry the evidence: the command you ran and its real
output, or the file and line you read.

A commit that corrects an earlier wrong claim or wrong code is its own commit,
and its body says what was wrong, how it was found, and what changed.

## Security

Do not open a public issue for a signature-correctness or key-handling bug. See
[SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
