# Root package boundary assessment

## Decision

Keep the signing, verification, inspection, planning, coordination, risk,
WebAuthn, and TUI APIs in the root `soroauth` package. Do not split the root
package in this change.

The root contains 31 production Go files (counted with
`git ls-files '*.go' | awk 'index($0,"/")==0 && $0 !~ /_test\\.go$/ {n++} END {print n}'`).
That is a meaningful maintenance surface, but file count alone does not show
that the package boundaries are independent. The dependency graph below shows
that the candidate seams share the same entry, signer, error, and inspection
types and call into one another in both directions across feature groupings.

## Dependency graph

Arrows mean that the source on the left directly calls or consumes declarations
from the source on the right. This is a partial graph of the meaningful
cross-file edges; ordinary type references within a feature are omitted.

```text
authorize ───────► preimage, address, delegates, signer
verify ──────────► preimage, address, delegates, signer
envelope ────────► authorize, preimage, inspect, verify
batch ───────────► authorize, delegates, inspect, verify
batch_sign ──────► batch, authorize
planner ─────────► address, delegates
coordinator ─────► address, authorize, preimage
risk ────────────► inspect, LedgerSource
diff ────────────► inspect, verify
tui ─────────────► authorize, delegates, diff, inspect, planner, risk, signer, verify

signer ──────────► webauthn, secp256r1
vault ───────────► signer
ledger ──────────► signer
```

An arrow points from a consumer file to the file whose declarations it uses.
`LedgerSource` is defined in `risk.go`; it is the narrow capability the risk
analyzer needs rather than a dependency on an RPC-client package.

Concrete call edges include:

| Source                  | Direct dependency                                                                                          | Evidence in source                                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `authorize.go`          | `preimage.go`, `signer.go`, `delegates.go`                                                                 | `AuthorizeEntry` builds `Preimage`, calls `Signer.Sign`, and validates/walks delegate credentials.                              |
| `verify.go`             | `preimage.go`, `signer.go`, `delegates.go`                                                                 | Verification rebuilds the signed payload, decodes classic-account signature values, and walks delegate nodes.                   |
| `envelope.go`           | `authorize.go`, `inspect.go`, `verify.go`, `preimage.go`                                                   | The envelope helpers expose entry-level authorization, inspection, verification, and payload operations over the same XDR tree. |
| `planner.go`            | `delegates.go`, `address.go`                                                                               | `Plan` uses `Delegate`, address parsing, `ValidateDelegateOrder`, and `PlannedTree.Wrap` calls `WithDelegates`.                 |
| `coordinator.go`        | `authorize.go`, `preimage.go`, `address.go`                                                                | `Coordinator.Record` calls `AuthorizeEntry`; its tree and state use the shared credential and address helpers.                  |
| `risk.go`               | `inspect.go`, `LedgerSource`                                                                               | `Analyze` starts with `Inspect`; `AnalyzeWithCurrentLedger` uses the small `LedgerSource` interface declared in `risk.go`.      |
| `tui.go`                | `inspect.go`, `risk.go`, `authorize.go`, `verify.go`, `diff.go`, `planner.go`, `delegates.go`, `signer.go` | The TUI renders inspection and risk results and composes signing, verification, diff, and delegate-planning operations.         |
| `signer.go`             | `webauthn.go`, `secp256r1.go`                                                                              | `NewPasskeySignerFromAssertion` uses the assertion parser and the P-256 helpers while returning the root `Signer` contract.     |
| `vault.go`, `ledger.go` | `signer.go`                                                                                                | The remote/device signer implementations satisfy the same root `Signer` interface.                                              |

These are not merely dependencies on a bottom-level encoding package: the
higher-level APIs reuse each other's public operations. For example, `Analyze`
depends on `Inspect`, the TUI depends on the analyzer and signing flows, `Plan`
produces the exact `Delegate` values accepted by `WithDelegates`, and
`Coordinator.Record` delegates the actual write to `AuthorizeEntry`.

## Why not split

1. The shared unit is already clear: the public entry points operate on
   `xdr.SorobanAuthorizationEntry`, its credential tree, and the same `Signer`
   interface. Moving these declarations into leaf packages would either make the
   shared types live in a new foundational package or make the packages import
   one another. The latter creates Go import cycles; the former changes the
   type-defining import path and requires a compatibility facade for the
   existing root API.
2. The apparent candidate packages are not independent. Planning, coordination,
   risk analysis, envelope helpers, verification, and the TUI all consume
   operations from the signing and inspection paths. A split would need a
   maintained dependency direction and wrappers for the root's exported surface,
   with no runtime or behavior requirement in this issue to justify that
   indirection.
3. The repository already separates actual boundaries: `cmd/soroauth` is the
   CLI, `server` and `remote` are transport-facing packages, `rpcflow` owns
   submission orchestration, and cloud/wallet integrations are under
   `adapters/`. In particular, adapters implement the root `Signer` interface;
   the root does not import those adapter modules.
4. The TUI is the least cohesive root feature, but its implementation composes
   the root API directly and has a `!js && !wasm` build constraint because its
   terminal dependencies do not belong in the wasm target. Extracting it while
   preserving the existing root `TUI` API would require a new dependency
   inversion or duplicated interfaces. That is a separate, evidence-backed
   extraction proposal, not a reason to split the authorization core now.

No source files or exported declarations are moved, so the existing public
import path and behavior remain unchanged. A compile-time compatibility snapshot
would add no evidence for this no-split decision; it is required if a future
change actually relocates declarations.

## Reconsideration criteria

Revisit this decision when a candidate package can be described as a directed
leaf with no dependency back into the root, has an independently useful API, and
has a concrete consumer or build/dependency benefit. Any such extraction must
preserve the root facade and prove the complete exported surface and the
golden/parity suites before and after the move.
