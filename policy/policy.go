// Package policy provides a Signer decorator that enforces caller-supplied
// rules against the decoded invocation tree before delegating to the wrapped
// signer. It builds on the risk analyzer so there is one set of heuristics
// with one set of documented limits.
//
// This package is unaudited. The wrapper's guarantees are only as strong as
// the analyzer's; see docs/analyzer-heuristics.md for what the analyzer
// misses. An allowlist is a real control; an amount check on an arbitrary
// ScVal argument is heuristic. Do not present the second as the first.
package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// ErrPolicyRefusal is returned when the policy wrapper refuses to sign
// because a rule was violated. It wraps soroauth.ErrPolicyRefusal so
// errors.Is works with the sentinel.
type ErrPolicyRefusal struct {
	Rule  string
	Node  string
	Cause error
}

// Error implements the error interface.
func (e *ErrPolicyRefusal) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("policy refusal: rule %q violated at %s: %v", e.Rule, e.Node, e.Cause)
	}
	return fmt.Sprintf("policy refusal: rule %q violated at %s", e.Rule, e.Node)
}

// Unwrap returns the underlying cause or the policy refusal sentinel.
func (e *ErrPolicyRefusal) Unwrap() error {
	if e.Cause != nil {
		return &wrappedError{cause: e.Cause, sentinel: soroauth.ErrPolicyRefusal}
	}
	return soroauth.ErrPolicyRefusal
}

type wrappedError struct {
	cause    error
	sentinel error
}

// Error implements the error interface.
func (w *wrappedError) Error() string { return w.cause.Error() }

// Unwrap returns the policy refusal sentinel.
func (w *wrappedError) Unwrap() error { return w.sentinel }

// PolicyRule is a rule that can approve or refuse a signing request based on
// the decoded authorization entry. Implementations must be safe for concurrent
// use.
type PolicyRule interface {
	// Name returns a unique identifier for this rule, used in refusal errors.
	Name() string
	// Evaluate returns an error if the entry violates the rule, or nil if it
	// passes. The error should describe what was violated and where.
	// credentialsKnown indicates whether the credentials type could be
	// determined from the preimage (true for ADDRESS_V2/ADDRESS_WITH_DELEGATES,
	// false for legacy SOURCE_ACCOUNT/ADDRESS).
	Evaluate(entry xdr.SorobanAuthorizationEntry, credentialsKnown bool) error
}

// PolicySigner wraps a Signer and enforces a set of PolicyRules before
// delegating to the inner signer. If any rule refuses, the inner signer is
// never invoked.
type PolicySigner struct {
	inner  soroauth.Signer
	rules  []PolicyRule
	cfg    *soroauth.RiskConfig
	verify func(xdr.SorobanAuthorizationEntry) error
}

// PolicySignerOption configures a PolicySigner.
type PolicySignerOption func(*PolicySigner)

// WithRiskConfig sets the risk configuration used for structural analysis.
// If not provided, soroauth.DefaultRiskConfig is used.
func WithRiskConfig(cfg *soroauth.RiskConfig) PolicySignerOption {
	return func(p *PolicySigner) {
		if cfg != nil {
			p.cfg = cfg
		}
	}
}

// WithCustomVerifier sets a custom verification function that is called
// after all rules pass. This can be used for additional checks that need
// the full entry. If it returns an error, the inner signer is not invoked.
func WithCustomVerifier(fn func(xdr.SorobanAuthorizationEntry) error) PolicySignerOption {
	return func(p *PolicySigner) {
		p.verify = fn
	}
}

// NewPolicySigner creates a signer that enforces rules before delegating to
// inner. The rules are evaluated in order; the first refusal stops evaluation.
// If inner is nil, NewPolicySigner panics.
func NewPolicySigner(inner soroauth.Signer, rules []PolicyRule, opts ...PolicySignerOption) *PolicySigner {
	if inner == nil {
		panic("policy: NewPolicySigner called with nil inner signer")
	}
	p := &PolicySigner{
		inner: inner,
		rules: rules,
		cfg:   nil, // will use default in Evaluate
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Address returns the inner signer's address.
func (p *PolicySigner) Address() string {
	return p.inner.Address()
}

// Sign evaluates all rules against the preimage's authorization entry. If any
// rule refuses, the inner signer is never called and ErrPolicyRefusal is
// returned. If the entry cannot be decoded for evaluation, signing is refused
// (fail closed).
func (p *PolicySigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("policy: sign: %w", err)
	}

	// Extract the authorization entry from the preimage for evaluation.
	entry, credentialsKnown, err := extractEntryFromPreimage(preimage)
	if err != nil {
		// Fail closed: if we can't decode the entry, we can't evaluate rules.
		return xdr.ScVal{}, &ErrPolicyRefusal{
			Rule:  "decode",
			Node:  "preimage",
			Cause: fmt.Errorf("failed to extract entry from preimage: %w", err),
		}
	}

	// Run structural analysis first; critical findings are treated as refusals.
	if p.cfg == nil {
		defaultCfg := soroauth.DefaultRiskConfig()
		p.cfg = &defaultCfg
	}
	findings, err := soroauth.Analyze(entry, p.cfg)
	if err != nil {
		return xdr.ScVal{}, &ErrPolicyRefusal{
			Rule:  "analyze",
			Node:  "entry",
			Cause: fmt.Errorf("risk analysis failed: %w", err),
		}
	}
	for _, f := range findings {
		if f.Severity == soroauth.SeverityCritical {
			return xdr.ScVal{}, &ErrPolicyRefusal{
				Rule:  "risk:" + f.Code,
				Node:  "entry",
				Cause: errors.New(f.Description),
			}
		}
	}

	// Evaluate each policy rule.
	for _, rule := range p.rules {
		if err := rule.Evaluate(entry, credentialsKnown); err != nil {
			return xdr.ScVal{}, &ErrPolicyRefusal{
				Rule:  rule.Name(),
				Node:  locateViolation(entry, err),
				Cause: err,
			}
		}
	}

	// Run custom verifier if provided.
	if p.verify != nil {
		if err := p.verify(entry); err != nil {
			return xdr.ScVal{}, &ErrPolicyRefusal{
				Rule:  "custom",
				Node:  "entry",
				Cause: err,
			}
		}
	}

	// All checks passed; delegate to inner signer.
	return p.inner.Sign(ctx, preimage, payload)
}

// extractEntryFromPreimage reconstructs the SorobanAuthorizationEntry from the
// preimage so rules can evaluate it. This is a best-effort reconstruction;
// if it fails, signing is refused (fail closed).
//
// Returns the entry and a flag indicating whether the credentials type could
// be determined from the preimage. For ENVELOPE_TYPE_SOROBAN_AUTHORIZATION
// (legacy), the credentials type is ambiguous between SOURCE_ACCOUNT and
// legacy ADDRESS, so credentialsKnown will be false.
func extractEntryFromPreimage(preimage xdr.HashIdPreimage) (xdr.SorobanAuthorizationEntry, bool, error) {
	var entry xdr.SorobanAuthorizationEntry
	credentialsKnown := false

	// The preimage contains the credentials and root invocation. We need to
	// reconstruct the full entry. The credentials arm tells us which variant.
	switch preimage.Type {
	case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization:
		if preimage.SorobanAuthorization == nil {
			return entry, false, errors.New("preimage: missing SorobanAuthorization")
		}
		// This preimage variant is used for both SOURCE_ACCOUNT and legacy
		// ADDRESS credentials. We cannot distinguish them from the preimage
		// alone, as both produce the same preimage structure (without address).
		// We default to SOURCE_ACCOUNT but mark credentials as unknown.
		entry.Credentials.Type = xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount
		entry.RootInvocation = preimage.SorobanAuthorization.Invocation

	case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress:
		if preimage.SorobanAuthorizationWithAddress == nil {
			return entry, false, errors.New("preimage: missing SorobanAuthorizationWithAddress")
		}
		// This variant is used for ADDRESS_V2 and ADDRESS_WITH_DELEGATES,
		// both of which bind the address in the payload.
		entry.Credentials.Type = xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2
		entry.Credentials.AddressV2 = &xdr.SorobanAddressCredentials{
			Address:                   preimage.SorobanAuthorizationWithAddress.Address,
			Nonce:                     preimage.SorobanAuthorizationWithAddress.Nonce,
			SignatureExpirationLedger: preimage.SorobanAuthorizationWithAddress.SignatureExpirationLedger,
		}
		entry.RootInvocation = preimage.SorobanAuthorizationWithAddress.Invocation
		credentialsKnown = true

	default:
		return entry, false, fmt.Errorf("preimage: unsupported type %v", preimage.Type)
	}

	return entry, credentialsKnown, nil
}

// locateViolation attempts to produce a human-readable location for a rule
// violation within the entry. This is best-effort; if it cannot determine a
// specific node, it returns "entry".
func locateViolation(entry xdr.SorobanAuthorizationEntry, err error) string {
	// For now, return the root invocation's contract address as a location.
	// Rules should include more specific location in their error messages.
	if entry.RootInvocation.Function.ContractFn != nil {
		if entry.RootInvocation.Function.ContractFn.ContractAddress.ContractId != nil {
			return contractIdToString(entry.RootInvocation.Function.ContractFn.ContractAddress.ContractId)
		}
	}
	return "entry"
}

// Compile-time check that PolicySigner satisfies soroauth.Signer.
var _ soroauth.Signer = (*PolicySigner)(nil)
