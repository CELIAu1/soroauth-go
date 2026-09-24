# soroauth

soroauth builds, signs and inspects Soroban authorization entries in Go. When a
contract calls `require_auth()` on an address that is not the transaction's
source account, the transaction has to carry a signed `SorobanAuthorizationEntry`
for that address — and the signature is not over the entry, but over a
`HashIdPreimage` whose shape depends on which credential arm is in use. The Go
SDK ships all of those XDR types and none of the code that builds or signs those
preimages. soroauth is that code, for all three address credential arms: legacy
`SOROBAN_CREDENTIALS_ADDRESS`, CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_V2`, and
CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` including nested delegate
trees.

## Install

```sh
go get github.com/soroauth/soroauth-go
```

The CLI:

```sh
go install github.com/soroauth/soroauth-go/cmd/soroauth@latest
```

Requires Go 1.25.0 or later, and `github.com/stellar/go-stellar-sdk` v0.7.3 or
later.

## CLI

Every subcommand accepts `--json` to emit a single JSON object on stdout. On
success the object carries the result fields; on failure it carries an `error`
field. Nothing else is written to stdout in JSON mode, so scripts can safely
pipe the output to `jq` without stripping usage text.

| subcommand | success fields | failure field |
|---|---|---|
| `payload` | `preimage`, `payload` | `error` |
| `sign` | `signed_entry` | `error` |
| `delegates` | `wrapped_entry` | `error` |
| `inspect` | (the `EntryInfo` struct) | `error` |
| `doctor` | `checks`, `ok` | (checks carry their own `pass`/`detail`; see below) |
| `cross-compile` | `target`, `size`, `sha256` (one per line) | `error` |

### Worked invocation — JSON output

```sh
# What would this signer have to sign?
SEED=SABC... ./soroauth payload \
  --entry <base64> --valid-until 1234567 --network testnet --json |
  jq -r .payload

# Sign and get the entry back as JSON
SEED=SABC... ./soroauth sign \
  --entry <base64> --valid-until 1234567 --network testnet \
  --secret-env SEED --json |
  jq -r .signed_entry

# Wrap an entry with delegates, JSON out
./soroauth delegates \
  --entry <base64> --valid-until 1234567 \
  --delegate GAAAA... --delegate GBBBB... --json |
  jq -r .wrapped_entry
```

### Doctor — check the local environment for common first-run problems

Most first-run problems are environmental — an unreachable RPC endpoint, a
mistyped secret variable name, a Go toolchain older than this module needs —
and the error from `sign` or `payload` does not say so. `doctor` checks three
things and reports each as pass or fail: never printing a secret, only
whether it is set.

```sh
# Human-readable
./soroauth doctor --rpc-url https://soroban-testnet.stellar.org --secret-env SEED

# JSON
./soroauth doctor --rpc-url https://soroban-testnet.stellar.org --secret-env SEED --json
```

```json
{"checks":[{"name":"go toolchain","pass":true,"detail":"go1.25.4"},{"name":"network","pass":true,"detail":"https://soroban-testnet.stellar.org reachable (HTTP 405)"},{"name":"secret env: SEED","pass":true,"detail":"SEED is set"}],"ok":true}
```

`--secret-env` is optional; when omitted, that check is skipped rather than
reported as a failure. `--rpc-url` defaults to the public testnet RPC, and any
HTTP response — including a non-2xx status — counts the network check as
passing, since it proves DNS, TCP and TLS all worked; only a transport-level
error (DNS failure, connection refused, timeout) fails it. Exit code is 0 when
every check passes, 1 if any fails.

### Cross-compile — build binaries for multiple targets

The `cross-compile` subcommand builds soroauth for any GOOS/GOARCH pair. It is
useful for creating release artifacts or verifying that the codebase compiles
cleanly on all targets.

```sh
# Human-readable output for the default matrix (all 5 release targets)
./soroauth cross-compile

# Build only linux/amd64 and windows/amd64, emit JSON (one object per line)
./soroauth cross-compile --targets linux/amd64,windows/amd64 --json

# Write binaries to a directory instead of just printing metadata
./soroauth cross-compile --targets linux/amd64 --output-dir ./dist
```

Sample JSON output:

```json
{"target":{"goos":"linux","goarch":"amd64","binary":"soroauth"},"size":4190368,"sha256":"1d214924a4717228e2c0b694c4b4d3c3077c29ed036d9b00805e431b4a6e8433"}
{"target":{"goos":"windows","goarch":"amd64","binary":"soroauth.exe"},"size":4308992,"sha256":"d241d7f7ab8ff20215fbb254abc4eb71643408f62cffc3c0989e552801ae75e4"}
```

On error, JSON mode emits a single object to stdout with an `error` field
(and nothing to stderr):

```json
{"target":{"goos":"invalid","goarch":"target","binary":""},"error":"invalid target \"invalid/target\": unknown GOOS/GOARCH"}
```

#### CI cross-compilation matrix

The CI workflow (`.github/workflows/ci.yml`) includes a `cross-compile` job
that runs on every push and PR. It builds for the five release targets in
parallel with a 5-minute timeout per platform:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

The job is build-only (no tests, no artifacts uploaded) and runs a smoke test
(`./soroauth help`) on the native platform to verify the binary runs. Failures
are named by platform in the workflow UI.

To reproduce a CI failure locally:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o soroauth-arm64 ./cmd/soroauth
./soroauth-arm64 help
```

### Release workflow

The project uses a GitHub Actions workflow (`.github/workflows/release.yml`) that
runs on version tags (`v*`). It:

1. Regenerates the golden vectors from the pinned JS SDK and fails if they
   drift (the same check that runs on every push).
2. Builds the CLI for `linux/amd64`, `linux/arm64`, `darwin/amd64`,
   `darwin/arm64`, `windows/amd64`.
3. Creates a GitHub Release whose notes are extracted from `CHANGELOG.md` for
   the tagged version.
4. Attaches all six binaries to the release.

To cut a release:

```sh
# Update CHANGELOG.md with the new version's entries
git tag v0.2.0
git push origin v0.2.0
```

The workflow will refuse to publish if the golden drift check fails, so a
release is only created when the library is provably byte-identical to the
reference implementation.

## Quickstart

Simulation tells you which addresses must authorize a call. Hand those entries
to soroauth, and put the signed ones back on the operation:

```go
sim, err := client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
    Transaction: encodedTx,
    AuthMode:    rpc.AuthModeRecord,
})
if err != nil {
    return err
}

entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*sim.Results[0].AuthXDR))
for _, encoded := range *sim.Results[0].AuthXDR {
    var entry xdr.SorobanAuthorizationEntry
    if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
        return err
    }
    entries = append(entries, entry)
}

ledger, err := client.GetLatestLedger(ctx)
if err != nil {
    return err
}
validUntil, err := soroauth.ExpirationAfter(ledger.Sequence, 1000)
if err != nil {
    return err
}

signed, err := soroauth.AuthorizeAll(ctx, entries,
    []soroauth.Signer{soroauth.NewEd25519Signer(sender)},
    validUntil, network.TestNetworkPassphrase)
if err != nil {
    return err // nothing partial is ever returned
}

op.Auth = signed // then re-simulate in enforce mode, assemble, sign, submit
```

This example is compiled by CI as `internal/readmesnippets/quickstart.go` —
see [Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

Source-account entries pass straight through untouched, so you can hand over
everything simulation returned without sorting by arm first.

## Credential types

| Arm | Value | Preimage variant | Address in the signed bytes? |
|---|---|---|---|
| `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` | 0 | none — the envelope signature covers it | n/a |
| `SOROBAN_CREDENTIALS_ADDRESS` | 1 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` (9) | no |
| `SOROBAN_CREDENTIALS_ADDRESS_V2` | 2 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10) | yes |
| `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` | 3 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10), bound to the **top-level** address | yes |

The legacy arm is defined by CAP-46-11; V2 and the delegated-signer arm by
CAP-71-01 and CAP-71-02. V2 binds the signer's address into the signed payload,
which closes a narrow replay case: one key shared across several accounts,
combined with a contract that does not itself bind the address into its
arguments.

`UpgradeToV2` converts an unsigned legacy entry to V2. You may need it:
simulation can return either arm, and the RPC's `UseUpgradedAuth` flag is
best-effort — it affects only the recording auth modes and is ignored by
protocol versions whose host cannot emit AddressV2.

## Delegates

Under CAP-71-01 an account can authorize through delegated signers instead of
signing itself. Every node in the tree — the account and every delegate at every
depth — signs **one** payload, bound to the top-level address.

```go
wrapped, err := soroauth.WithDelegates(entry, validUntil,
    []soroauth.Delegate{
        {Address: d1},
        {Address: d2, Nested: []soroauth.Delegate{{Address: d3}}},
    }, nil) // nil top-level signature → ScvVoid, which CAP-71-01 permits
if err != nil {
    return wrapped, err
}

for _, kp := range []*keypair.Full{k1, k2, k3} {
    wrapped, err = soroauth.AuthorizeEntry(ctx, wrapped,
        soroauth.NewEd25519Signer(kp), validUntil, passphrase,
        soroauth.ForAddress(kp.Address()))
    if err != nil {
        return wrapped, err
    }
}
```

This example is compiled by CI as `internal/readmesnippets/delegates.go` — see
[Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

Each delegates array is sorted by the XDR encoding of the address and checked
for duplicates within that level, as CAP-71-01 requires; the same address at two
*different* levels is allowed, and one `AuthorizeEntry` call fills every node
carrying that address.

Because every node commits to the same payload, the expiration is fixed once any
node is signed: signing another node at a different `validUntilLedger` would
leave the entry's signatures disagreeing, so soroauth refuses it.

Replacing one delegate's signature needs `AllowResign`, scoped to that
delegate's address so the override does not also apply to a different call
touching another node in the same entry:

```go
resigned, err := soroauth.AuthorizeEntry(ctx, wrapped, soroauth.NewEd25519Signer(k1),
    validUntil, passphrase, soroauth.ForAddress(d1), soroauth.AllowResign(d1))
```

This example is compiled by CI as `internal/readmesnippets/allowresign.go` —
see [Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

`AllowResign()` with no arguments keeps its original, unscoped meaning: the
guard is lifted for whatever address that call targets. Naming one or more
addresses restricts it to those; a target outside the list still refuses with
`ErrAlreadySigned`. Either way, the expiration guard above is never lifted.

One consequence worth stating plainly: the delegates arm and V2 share the same
address-bound preimage, so the same address, nonce, invocation, expiration and
network produce an **identical payload** on both arms — golden vectors 3 and 6
show exactly that. Replay protection comes from the nonce, which the host
consumes; this is by design under CAP-71-01, not a defect.

`AuthorizeAll` applies every signer matching any node in the tree. It does not
fail when a delegate has no signer, because it cannot know the account's policy.

An unsigned node fails only if the account's `__check_auth` calls
`delegate_account_auth` for that address — the host then runs that delegate's
`__check_auth` with whatever signature the node carries (CAP-71-01,
*Semantics → `delegate_account_auth` function*), and an empty one is not
something a G-account delegate can authenticate with. The pattern the CAP
recommends, and the one soroban-sdk's `delegate_auth` documentation and this
repo's e2e fixture both follow, delegates to *every* listed signer. So unless
you know your account's policy, treat an unsigned node as one that will fail:
check the per-node `Signed` flags from `Inspect` before submitting.

## Expiration

`ExpirationAfter(latestLedger, ledgers)` turns a lifetime into the absolute
ledger an entry must carry. Two things about that number, both read from the
host rather than inferred:

- **It is inclusive.** `verify_and_consume_nonce` rejects only when
  `ledger_seq > live_until_ledger`, so the expiration ledger itself is still
  valid. The JS SDK's doc comment describes the bound as exclusive; the host is
  the authority.
- **There is an upper bound this library cannot enforce.** The host also rejects
  anything above the network's `max_live_until_ledger`. That is a network
  setting, so it is deliberately not hard-coded here — a baked-in constant would
  silently become wrong. Read it from the network if you need the real ceiling.

Zero is refused: by the rule above it is already expired, not permissive.

## Differences from the JS SDK

soroauth is proven byte-for-byte against `@stellar/stellar-sdk@17.1.0`, and
deviates from it in four deliberate ways.

- **A signature is only ever written to a node whose address matches the
  target** — `ForAddress`, or the signer's own `Address()`. The JS reference
  falls back to the top-level node when no target is given, even if the key
  belongs to someone else. soroauth returns `ErrNoMatchingCredentialNode`
  instead, because a signature on the wrong node is a transaction that pays fees
  and then fails.
- **No default write to the top-level node**, for the same reason.
- **The signer is never invoked when nothing matches.** The zero-match check and
  the already-signed check run *before* signing, so a hardware wallet or remote
  signer is never asked to approve something that is about to be discarded.
- **`AccountMultiSigner`** has no JS equivalent. It signs for a classic account
  with several keys, sorted strictly ascending by raw public key and capped at
  20, which is what the host requires.

soroauth is also stricter in one place: wrapping or upgrading an entry that
already carries a signature returns `ErrAlreadySigned`, where JS silently
discards the old signature. The payload changes under both operations, so that
signature would no longer verify.

## Proven on testnet

Every claim below is backed by a transaction that exists on chain. Full detail,
including raw host errors, is in [e2e/RESULTS.md](e2e/RESULTS.md).

| Scenario | Result | Transaction |
|---|---|---|
| Legacy `ADDRESS` accepted | accepted | [`6d77c01a…`](https://stellar.expert/explorer/testnet/tx/6d77c01affa11766979ad905e68d32a61a6e3daa6a110096ce7bb4698376a182) |
| CAP-71 `ADDRESS_V2` accepted | accepted | [`566dcdac…`](https://stellar.expert/explorer/testnet/tx/566dcdacee95e2e44646099b78de46208f1b1c2b18bc0c818dcdae2349d85661) |
| `AccountMultiSigner` meets a 2-of-2 threshold | accepted | [`9914176a…`](https://stellar.expert/explorer/testnet/tx/9914176a36dd314927aa830930a57c2bd85254a8bef659b1d88e13408a82459f) |
| One signature does **not** meet that threshold | rejected, as it must be | [`5b0b49e7…`](https://stellar.expert/explorer/testnet/tx/5b0b49e75e958feff7152b359039996ca57f28ee371e2207633ec645a7faa6c6) |
| Delegated signers accepted, account itself unsigned | accepted | [`5cd87e73…`](https://stellar.expert/explorer/testnet/tx/5cd87e7397b0936550875944d8f8df217ee75b438a5c706c31565c89cd2ccf2a) |
| An unregistered delegate is refused | rejected, as it must be | [`9afda479…`](https://stellar.expert/explorer/testnet/tx/9afda479a6b5bad8cdefd4c35956aaf2a1ba15e13f394b818a3db8d392f52fdd) |

The two rejection rows matter as much as the acceptances: they assert the host's
specific reason, so the accepting scenarios cannot be passing by accident.

Offline, nine golden vectors generated by `@stellar/stellar-sdk@17.1.0` assert
that soroauth's preimage, payload hash and final signed entry are byte-identical
to the reference, and CI regenerates them on every push to catch drift.

## Status

**v0.1.0. Unaudited.** The wire format is fixed by the protocol and pinned by
the golden vectors, but this library is new and has not been reviewed by anyone
outside its author. Read the code before you sign anything valuable with it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Golden vectors are never edited by hand.
Security reports go through [SECURITY.md](SECURITY.md), not the issue tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
