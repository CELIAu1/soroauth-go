package soroauth

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// FindingSeverity ranks the importance of a finding.
type FindingSeverity string

// The three severities a Finding can carry, in increasing order of
// importance: info notes a fact worth surfacing, warning flags something a
// signer should look at before approving, and critical flags something the
// analyzer believes should block signing outright.
const (
	SeverityInfo     FindingSeverity = "info"
	SeverityWarning  FindingSeverity = "warning"
	SeverityCritical FindingSeverity = "critical"
)

// Finding represents a single risk finding from analyzing an authorization entry.
type Finding struct {
	Code        string          `json:"code"`
	Severity    FindingSeverity `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Rationale   string          `json:"rationale"`
}

// String renders the finding for a terminal.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s\n  %s\n  rationale: %s",
		f.Severity, f.Code, f.Title, f.Description, f.Rationale)
}

// RiskConfig controls the heuristics used by Analyze. All zero values are
// conservative defaults suitable for production use.
type RiskConfig struct {
	// MaxDelegateDepth is the maximum allowed nesting depth of delegates
	// before a warning is emitted. Default 3.
	MaxDelegateDepth int

	// MaxTotalDelegates is the maximum total delegate nodes (all levels)
	// before a warning is emitted. Default 10.
	MaxTotalDelegates int

	// MaxValidUntilLedgerDelta is the maximum number of ledgers into the
	// future that ValidUntilLedger may be relative to the provided
	// currentLedger before a warning is emitted. Default 10000 (roughly
	// 2.5 hours at 5s/ledger).
	MaxValidUntilLedgerDelta uint32

	// KnownContracts is a set of contract addresses (C...) that are
	// considered familiar. Contracts not in this set trigger a warning.
	// Empty means no contract checking is performed.
	KnownContracts map[string]bool

	// MaxSubInvocations is the maximum total sub-invocations before a
	// warning is emitted. Default 50.
	MaxSubInvocations int

	// CurrentLedger is the ledger sequence to compare ValidUntilLedger
	// against. If zero, far-future expiration checking is skipped.
	CurrentLedger uint32
}

// DefaultRiskConfig returns a configuration with conservative defaults.
func DefaultRiskConfig() RiskConfig {
	return RiskConfig{
		MaxDelegateDepth:         3,
		MaxTotalDelegates:        10,
		MaxValidUntilLedgerDelta: 10000,
		KnownContracts:           make(map[string]bool),
		MaxSubInvocations:        50,
		CurrentLedger:            0,
	}
}

// Analyze examines an authorization entry and returns a list of findings
// ranked by severity (critical first, then warning, then info).
//
// This is a structural analysis only. It does not decode contract arguments,
// verify contract behavior, or provide any safety guarantee. It surfaces
// patterns that operators commonly want to review before signing.
//
// The heuristics are controlled by cfg. A nil cfg uses DefaultRiskConfig.
func Analyze(entry xdr.SorobanAuthorizationEntry, cfg *RiskConfig) ([]Finding, error) {
	if cfg == nil {
		defaultCfg := DefaultRiskConfig()
		cfg = &defaultCfg
	}

	var findings []Finding

	info, err := Inspect(entry)
	if err != nil {
		return nil, fmt.Errorf("soroauth: analyze: %w", err)
	}

	// Check for source account credentials with delegates (malformed entry)
	// This checks the raw XDR since Inspect only reports delegates for the
	// delegates arm.
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount &&
		entry.Credentials.AddressWithDelegates != nil &&
		len(entry.Credentials.AddressWithDelegates.Delegates) > 0 {
		findings = append(findings, Finding{
			Code:        "SOURCE_ACCOUNT_WITH_DELEGATES",
			Severity:    SeverityCritical,
			Title:       "Source account credentials with delegates",
			Description: "Source account arm does not support delegates; this entry is malformed",
			Rationale:   "The SOURCE_ACCOUNT credential arm has no delegate structure. Presence of delegates indicates a malformed entry that will fail on-chain.",
		})
	}

	// Check delegate tree depth and breadth
	findings = append(findings, analyzeDelegates(info.Delegates, 1, cfg)...)

	// Check total delegate count
	totalDelegates := countTotalDelegates(info.Delegates)
	if totalDelegates > cfg.MaxTotalDelegates {
		findings = append(findings, Finding{
			Code:        "DELEGATE_COUNT_HIGH",
			Severity:    SeverityWarning,
			Title:       "High number of delegate signers",
			Description: fmt.Sprintf("Entry has %d total delegate nodes (limit: %d)", totalDelegates, cfg.MaxTotalDelegates),
			Rationale:   "Each delegate must sign the same payload. Many delegates increase coordination complexity and the chance of a signer rejecting or being unavailable.",
		})
	}

	// Check sub-invocation count
	if info.SubInvocations > cfg.MaxSubInvocations {
		findings = append(findings, Finding{
			Code:        "SUB_INVOCATION_COUNT_HIGH",
			Severity:    SeverityWarning,
			Title:       "Deep or broad invocation tree",
			Description: fmt.Sprintf("Entry authorizes %d sub-invocations (limit: %d)", info.SubInvocations, cfg.MaxSubInvocations),
			Rationale:   "Each sub-invocation is a nested contract call. Complex trees are harder to audit and may indicate a contract doing more than expected.",
		})
	}

	// Check expiration ledger
	if cfg.CurrentLedger > 0 && info.ValidUntilLedger > 0 {
		delta := info.ValidUntilLedger - cfg.CurrentLedger
		if delta > cfg.MaxValidUntilLedgerDelta {
			findings = append(findings, Finding{
				Code:        "EXPIRATION_FAR_FUTURE",
				Severity:    SeverityWarning,
				Title:       "Signature expiration far in the future",
				Description: fmt.Sprintf("Valid until ledger %d (current: %d, delta: %d, limit: %d)", info.ValidUntilLedger, cfg.CurrentLedger, delta, cfg.MaxValidUntilLedgerDelta),
				Rationale:   "A distant expiration means the signature can be reused for longer. If the signed invocation is malicious or buggy, the window for abuse is larger.",
			})
		}
	}

	// Check for unknown contracts
	if info.RootContract != "" && len(cfg.KnownContracts) > 0 {
		if !cfg.KnownContracts[info.RootContract] {
			findings = append(findings, Finding{
				Code:        "CONTRACT_UNKNOWN",
				Severity:    SeverityWarning,
				Title:       "Unfamiliar contract address",
				Description: fmt.Sprintf("Root contract %s is not in the known contracts list", info.RootContract),
				Rationale:   "Signing an invocation for an unknown contract means you cannot verify its behavior. Add known contract addresses to RiskConfig.KnownContracts to suppress this.",
			})
		}
	}

	// Check for unsigned delegate nodes when there are delegates
	if info.CredentialType == CredentialTypeAddressWithDelegates && len(info.Delegates) > 0 {
		unsignedCount := countUnsignedDelegates(info.Delegates)
		if unsignedCount > 0 {
			findings = append(findings, Finding{
				Code:        "UNSIGNED_DELEGATES",
				Severity:    SeverityInfo,
				Title:       "Some delegates not yet signed",
				Description: fmt.Sprintf("%d of %d delegate nodes are unsigned", unsignedCount, totalDelegates),
				Rationale:   "Unsigned delegates mean the entry is not yet ready for submission. This is informational; the entry will be rejected on-chain if submitted incomplete.",
			})
		}
	}

	// Check for zero expiration (already expired)
	if info.ValidUntilLedger == 0 && info.CredentialType != CredentialTypeSourceAccount {
		findings = append(findings, Finding{
			Code:        "EXPIRATION_ZERO",
			Severity:    SeverityCritical,
			Title:       "Signature expiration is zero (already expired)",
			Description: "ValidUntilLedger is 0, which the host treats as already expired",
			Rationale:   "The host rejects signatures where current_ledger > signatureExpirationLedger. A value of 0 means the signature expired at genesis.",
		})
	}

	// Check for source account credentials with delegates (shouldn't happen but validate)
	if info.CredentialType == CredentialTypeSourceAccount && len(info.Delegates) > 0 {
		findings = append(findings, Finding{
			Code:        "SOURCE_ACCOUNT_WITH_DELEGATES",
			Severity:    SeverityCritical,
			Title:       "Source account credentials with delegates",
			Description: "Source account arm does not support delegates; this entry is malformed",
			Rationale:   "The SOURCE_ACCOUNT credential arm has no delegate structure. Presence of delegates indicates a malformed entry that will fail on-chain.",
		})
	}

	// Check for legacy address credentials (not address-bound)
	if info.CredentialType == CredentialTypeAddress && !info.AddressBound {
		findings = append(findings, Finding{
			Code:        "LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND",
			Severity:    SeverityInfo,
			Title:       "Legacy address credentials (not address-bound)",
			Description: "Entry uses SOROBAN_CREDENTIALS_ADDRESS which does not bind the signer address into the payload",
			Rationale:   "Legacy credentials are vulnerable to a narrow replay case where a signature for one account could be replayed for another if they share a signing key and the contract doesn't bind the address in its arguments. V2 credentials (ADDRESS_V2 or ADDRESS_WITH_DELEGATES) close this.",
		})
	}

	// Sort findings by severity: critical > warning > info
	severityOrder := map[FindingSeverity]int{
		SeverityCritical: 0,
		SeverityWarning:  1,
		SeverityInfo:     2,
	}
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if severityOrder[findings[j].Severity] < severityOrder[findings[i].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}

	return findings, nil
}

// analyzeDelegates recursively checks delegate tree depth.
func analyzeDelegates(delegates []NodeInfo, depth int, cfg *RiskConfig) []Finding {
	var findings []Finding
	for _, d := range delegates {
		if depth > cfg.MaxDelegateDepth {
			findings = append(findings, Finding{
				Code:        "DELEGATE_DEPTH_EXCEEDED",
				Severity:    SeverityWarning,
				Title:       "Delegate nesting exceeds recommended depth",
				Description: fmt.Sprintf("Delegate %s at depth %d (max recommended: %d)", d.Address, depth, cfg.MaxDelegateDepth),
				Rationale:   "Deeply nested delegates are harder to audit and each level adds a signer that must approve. CAP-71-01 permits arbitrary nesting but operational complexity grows quickly.",
			})
		}
		if len(d.Nested) > 0 {
			findings = append(findings, analyzeDelegates(d.Nested, depth+1, cfg)...)
		}
	}
	return findings
}

func countTotalDelegates(delegates []NodeInfo) int {
	count := 0
	for _, d := range delegates {
		count++
		count += countTotalDelegates(d.Nested)
	}
	return count
}

func countUnsignedDelegates(delegates []NodeInfo) int {
	count := 0
	for _, d := range delegates {
		if !d.Signed {
			count++
		}
		count += countUnsignedDelegates(d.Nested)
	}
	return count
}

// LedgerSource is the minimal RPC client capability AnalyzeWithCurrentLedger
// needs: just enough to read the current ledger, so callers do not have to
// satisfy a wider RPC client interface just to get expiration checking.
type LedgerSource interface {
	GetLatestLedger(ctx context.Context) (uint32, error)
}

// AnalyzeWithCurrentLedger is a convenience wrapper that fetches the current
// ledger from src and runs Analyze with it.
//
// This is for callers who want expiration checking but don't want to manage
// ledger state themselves. The RPC call is best-effort; if it fails, analysis
// proceeds without expiration checking (equivalent to CurrentLedger=0), since
// a failed status lookup should degrade the analysis rather than block it.
func AnalyzeWithCurrentLedger(ctx context.Context, entry xdr.SorobanAuthorizationEntry, cfg *RiskConfig, src LedgerSource) ([]Finding, error) {
	if cfg == nil {
		defaultCfg := DefaultRiskConfig()
		cfg = &defaultCfg
	}
	if cfg.CurrentLedger == 0 && src != nil {
		ledger, err := src.GetLatestLedger(ctx)
		if err == nil {
			cfg.CurrentLedger = ledger
		}
	}
	return Analyze(entry, cfg)
}

// context is imported for the LedgerSource method signature
