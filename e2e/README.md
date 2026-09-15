# End-to-end tests

These tests prove soroauth against a live Stellar network. They are the evidence
behind the claim that the signatures this library produces are accepted by a
real host — not by a mock, and not only by the JS reference implementation.

They are excluded from the normal test suite by the `e2e` build tag, because
they create accounts, submit transactions, and wait on ledger close.

## Running them

```sh
cd e2e/contracts && stellar contract build    # once, produces the fixture wasm
cd ../.. && go test -tags e2e -v ./e2e/...
```

By default they run against `https://soroban-testnet.stellar.org`. Point them
elsewhere with `SOROAUTH_RPC_URL`. Whatever URL is used is verified with live
`getNetwork`, `getHealth` and `getLatestLedger` calls before anything relies on
it, and the passphrase and protocol version found are logged.

Every account is generated at runtime and funded by friendbot. No key is read
from disk, written to disk, or committed. Nothing here touches mainnet.

A full run takes roughly three minutes, most of it waiting for ledgers to close.

## What each scenario proves

| ID | Scenario | What it proves |
|----|----------|----------------|
| A | Legacy `SOROBAN_CREDENTIALS_ADDRESS` | An entry on the legacy arm, signed by soroauth, is accepted by the host. |
| B | CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_V2` | The address-bound arm is accepted. The test reports whether simulation returned V2 directly or whether `UpgradeToV2` was needed. |
| C | `AccountMultiSigner` | A multi-key signature vector meets a 2-of-2 medium threshold on a classic account. This signer has no JS equivalent, so the golden vectors cannot cover it; this is its proof. |
| D | CAP-71 delegated signers | A `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` entry with a `Void` top-level signature and two G-account delegates is accepted, so a contract account authenticates purely through its delegates. |
| E | The host rejects what it should | The same flow with a delegate the account never registered is refused by the contract's `__check_auth` with `UnknownDelegate`. |

Two of the tests exist only to stop the others passing for the wrong reason:

- **`TestScenarioCRejectsASingleSignature`** signs with one key against a
  threshold of two and requires the host to refuse. Without it, scenario C would
  pass just as happily against an account whose threshold was never raised, and
  would prove nothing about multisig.
- **Scenario E asserts the specific contract error code**, not merely that the
  transaction failed. This matters: an earlier version of the test passed while
  the transaction was actually running out of instructions before `__check_auth`
  was ever reached. Asserting `ContractCode 1` is what makes it prove the thing
  it claims.

## How a scenario works

CAP-71-01 needs two simulation passes, and the tests follow that:

1. **Simulate in record mode.** The host reports which addresses must authorize
   the call, and hands back unsigned authorization entries.
2. **Sign with soroauth.** For A, B and C this is `AuthorizeAll`. For D and E the
   recorded entry is first wrapped with `WithDelegates`, then each delegate is
   signed with `AuthorizeEntry` and `ForAddress`.
3. **Simulate in enforce mode**, carrying the signed entries, so the resource
   fee accounts for the signatures that are actually there.
4. **Assemble** — the Go SDK has no `assembleTransaction`, so the simulated
   `SorobanTransactionData` is attached to the operation explicitly and its
   resource fee set from the simulation's `minResourceFee`.
5. **Sign the envelope** as the payer and submit, then poll until it resolves.

The scenarios that are meant to be rejected skip step 3. That pass would fail
locally for the very reason under test, which would only show that simulation
agrees with the host; the point is to put the transaction in front of the real
host and watch it be refused there, after fees. Because the recording pass never
executed `__check_auth`, its instruction count is too low, so those submissions
are given extra instruction headroom — otherwise they run out of budget before
reaching the rejection under test.

The credential arm reported for each scenario is read back off the envelope that
was actually submitted, by decoding it again, rather than assumed from what the
test meant to build.

## The fixture contract

`contracts/modular-account` is a custom account that carries no signature of its
own and authorizes purely by forwarding to CAP-71 delegated signers. It exists
only so scenarios D and E have something to authenticate against.

It is deliberately not a product: no policies, no admin functions, no
upgradability, and no way to change the signer set after construction. Do not
deploy it to mainnet or use it as a smart-account starting point.

Its own unit tests (`cargo test -p modular-account`) cover constructor storage
and both rejection paths.

## RESULTS.md

`RESULTS.md` is written by a run, never by hand. It is only written when all five
scenarios ran in the same invocation, so it cannot be a partial record of a
single-scenario run. It carries the date, the network and protocol version, and
for every scenario the transaction hash, the ledger, the credential arm observed
on the submitted envelope, an explorer link, and — for scenario E — the raw host
error verbatim.
