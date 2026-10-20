# Implementation Plan for Issues #330, #331, #332, #333

## Issue #330: Policy-enforcing signer wrapper

**Location**: `policy/` package (new module) **Approach**: Create a
`PolicySigner` decorator that wraps any `Signer` and evaluates rules against the
decoded invocation tree using the existing risk analyzer.

### Key components:

- `PolicySigner` struct wrapping inner `Signer`
- `PolicyRule` interface for extensible rules
- Built-in rules: contract allowlist, max amount, forbidden SAC admin calls
- Uses `risk.Analyze` for structural analysis
- Distinct error type `ErrPolicyRefusal` (already exists in errors.go)
- Fail-closed: unevaluable trees are refused

## Issue #331: Turnkey signer

**Location**: `turnkey/` package (new module, separate go.mod) **Approach**:
Implement a `Signer` backed by Turnkey's API.

### Key components:

- `TurnkeySigner` struct implementing `soroauth.Signer`
- API client for Turnkey's signing endpoints
- Credential handling per Turnkey's documented scheme
- Offline tests with recorded HTTP fixtures (scrubbed of credentials)
- Distinct error for policy denial vs timeout
- No root-module dependency

## Issue #332: Fireblocks signer

**Location**: `fireblocks/` package (new module, separate go.mod) **Approach**:
Implement a `Signer` backed by Fireblocks' raw-signing API with async approval.

### Key components:

- `FireblocksSigner` struct implementing `soroauth.Signer`
- Async approval flow handled within `Sign` method
- Context-bound long waits with cancellation test
- Offline tests with recorded HTTP fixtures (approval, rejection, timeout)
- Distinct error for human rejection vs timeout

## Issue #333: Threshold signing with real key shares

**Location**: Replace `threshold.go` implementation **Approach**: Use
`github.com/bytemare/frost` with Ed25519 ciphersuite (RFC 9591).

### Key components:

- `FROSTThresholdSigner` coordinator implementation
- `FROSTPartySigner` for each participant holding a key share
- Two-round protocol: Commit -> Sign -> Aggregate
- Produces standard Ed25519 signatures (verified against `NewEd25519Signer`)
- Threat model documented: what it protects (key never reconstructed) and what
  it doesn't (side channels, malicious coordinator, etc.)
- Test vectors with known keys

### Interface considerations:

The current `ThresholdSigner` interface doesn't match FROST's two-round
protocol. Options:

1. Extend interface with `Commit` and `SignRound` methods
2. Keep coordinator/party separation but change API
3. Document that the old interface is deprecated

I'll go with option 2: new types `FROSTCoordinator` and `FROSTParticipant` that
work together, with the old `ThresholdSigner` marked deprecated.

---

## Implementation Order:

1. #330 Policy signer wrapper (builds on existing risk.go)
2. #333 Threshold signer (core crypto, affects interfaces)
3. #331 Turnkey signer (new module)
4. #332 Fireblocks signer (new module)

---

## Testing Strategy:

- All new signers pass `signertest.Run` conformance suite
- Offline tests with recorded HTTP fixtures for remote signers
- Golden vector tests for threshold signatures
- Cancellation/deadline tests for all context-aware signers
- Policy refusal tests with distinct error types
