// Package policy provides a Signer decorator that enforces caller-supplied
// rules against the decoded invocation tree before delegating to the wrapped
// signer.
package policy

import (
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// contractIdToString converts an xdr.ContractId to its C... string representation.
func contractIdToString(cid *xdr.ContractId) string {
	if cid == nil {
		return ""
	}
	address, err := strkey.Encode(strkey.VersionByteContract, cid[:])
	if err != nil {
		return fmt.Sprintf("invalid-contract-id-%x", cid[:])
	}
	return address
}

// ContractAllowlistRule refuses signing if the root contract or any
// sub-invocation calls a contract not in the allowlist.
type ContractAllowlistRule struct {
	allowed map[string]bool
}

// NewContractAllowlistRule creates a rule that only permits invocations
// targeting contracts in the allowlist. Addresses must be C... contract
// addresses.
func NewContractAllowlistRule(allowedContracts []string) (*ContractAllowlistRule, error) {
	allowed := make(map[string]bool, len(allowedContracts))
	for _, addr := range allowedContracts {
		if _, err := soroauth.ParseAddress(addr); err != nil {
			return nil, fmt.Errorf("policy: contract allowlist: invalid address %q: %w", addr, err)
		}
		allowed[addr] = true
	}
	return &ContractAllowlistRule{allowed: allowed}, nil
}

// Name returns the unique identifier for this rule.
func (r *ContractAllowlistRule) Name() string { return "contract_allowlist" }

// Evaluate returns an error if the entry violates the contract allowlist rule.
func (r *ContractAllowlistRule) Evaluate(entry xdr.SorobanAuthorizationEntry, credentialsKnown bool) error {
	// Check root invocation
	if err := r.checkInvocation(entry.RootInvocation, "root"); err != nil {
		return err
	}
	return nil
}

func (r *ContractAllowlistRule) checkInvocation(inv xdr.SorobanAuthorizedInvocation, path string) error {
	if inv.Function.ContractFn != nil {
		addr := inv.Function.ContractFn.ContractAddress
		if addr.Type == xdr.ScAddressTypeScAddressTypeContract && addr.ContractId != nil {
			contractStr := contractIdToString(addr.ContractId)
			if !r.allowed[contractStr] {
				return fmt.Errorf("contract %s not in allowlist (at %s)", contractStr, path)
			}
		}
	}
	// Recurse into sub-invocations
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocation(sub, fmt.Sprintf("%s/sub[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// MaxAmountRule refuses signing if any invocation argument that can be
// interpreted as an amount exceeds the configured maximum.
//
// WARNING: This is a HEURISTIC. It inspects ScVal arguments for numeric
// values (u64, i64, u128, i128) and compares them to the limit. It does not
// understand contract semantics — a large number in a nonce field, a
// timestamp, or an unrelated parameter would also trigger it. An allowlist
// is a real control; an amount check on an arbitrary ScVal argument is
// heuristic. Do not present the second as the first.
type MaxAmountRule struct {
	maxAmount uint64
}

// NewMaxAmountRule creates a rule that refuses any invocation argument
// whose numeric value exceeds maxAmount. Only unsigned 64-bit integers
// are checked; larger types (u128) are conservatively refused if they
// don't fit in uint64.
func NewMaxAmountRule(maxAmount uint64) *MaxAmountRule {
	return &MaxAmountRule{maxAmount: maxAmount}
}

// Name returns the unique identifier for this rule.
func (r *MaxAmountRule) Name() string { return "max_amount" }

// Evaluate returns an error if any invocation argument exceeds the max amount.
func (r *MaxAmountRule) Evaluate(entry xdr.SorobanAuthorizationEntry, credentialsKnown bool) error {
	return r.checkInvocationArgs(entry.RootInvocation, "root")
}

func (r *MaxAmountRule) checkInvocationArgs(inv xdr.SorobanAuthorizedInvocation, path string) error {
	if inv.Function.ContractFn != nil {
		for i, arg := range inv.Function.ContractFn.Args {
			if err := r.checkScVal(arg, fmt.Sprintf("%s/arg[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocationArgs(sub, fmt.Sprintf("%s/sub[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func (r *MaxAmountRule) checkScVal(val xdr.ScVal, location string) error {
	switch val.Type {
	case xdr.ScValTypeScvU64:
		if val.U64 != nil && uint64(*val.U64) > r.maxAmount {
			return fmt.Errorf("amount %d exceeds maximum %d at %s", *val.U64, r.maxAmount, location)
		}
	case xdr.ScValTypeScvI64:
		if val.I64 != nil && *val.I64 > 0 && uint64(*val.I64) > r.maxAmount {
			return fmt.Errorf("amount %d exceeds maximum %d at %s", *val.I64, r.maxAmount, location)
		}
	case xdr.ScValTypeScvU128:
		if val.U128 != nil {
			// u128 is two u64s (hi, lo). If hi > 0, it definitely exceeds uint64 max.
			hi, lo := val.U128.Hi, val.U128.Lo
			if hi > 0 || uint64(lo) > r.maxAmount {
				return fmt.Errorf("amount (u128) exceeds maximum %d at %s", r.maxAmount, location)
			}
		}
	case xdr.ScValTypeScvI128:
		if val.I128 != nil {
			hi, lo := val.I128.Hi, val.I128.Lo
			if hi > 0 || (hi == 0 && lo > 0 && uint64(lo) > r.maxAmount) {
				return fmt.Errorf("amount (i128) exceeds maximum %d at %s", r.maxAmount, location)
			}
		}
	case xdr.ScValTypeScvVec:
		if val.Vec != nil && *val.Vec != nil {
			vec := **val.Vec
			for i, elem := range vec {
				if err := r.checkScVal(elem, fmt.Sprintf("%s/vec[%d]", location, i)); err != nil {
					return err
				}
			}
		}
	case xdr.ScValTypeScvMap:
		if val.Map != nil && *val.Map != nil {
			m := **val.Map
			for i, kv := range m {
				if err := r.checkScVal(kv.Val, fmt.Sprintf("%s/map[%d]", location, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ForbiddenSACAdminRule refuses signing if the invocation targets a
// Soroban Authorization Contract (SAC) admin method. SAC admin methods
// include: set_admin, set_authorized, set_authorization_entry_ttl, etc.
// This is a structural check based on function name; it does not verify
// the contract is actually a SAC.
type ForbiddenSACAdminRule struct {
	// Additional forbidden function names beyond the default SAC admin set.
	Additional []string
}

var defaultSACAdminMethods = map[string]bool{
	"set_admin":                   true,
	"set_authorized":              true,
	"set_authorization_entry_ttl": true,
	"upgrade":                     true,
	"set_contract_id":             true,
	"set_spec_entries":            true,
}

// Name returns the unique identifier for this rule.
func (r *ForbiddenSACAdminRule) Name() string { return "forbidden_sac_admin" }

// Evaluate returns an error if any invocation calls a forbidden SAC admin method.
func (r *ForbiddenSACAdminRule) Evaluate(entry xdr.SorobanAuthorizationEntry, credentialsKnown bool) error {
	forbidden := make(map[string]bool)
	for k, v := range defaultSACAdminMethods {
		forbidden[k] = v
	}
	for _, name := range r.Additional {
		forbidden[name] = true
	}
	return r.checkInvocation(entry.RootInvocation, "root", forbidden)
}

func (r *ForbiddenSACAdminRule) checkInvocation(inv xdr.SorobanAuthorizedInvocation, path string, forbidden map[string]bool) error {
	if inv.Function.ContractFn != nil {
		fn := string(inv.Function.ContractFn.FunctionName)
		if forbidden[fn] {
			return fmt.Errorf("forbidden SAC admin method %q called at %s", fn, path)
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocation(sub, fmt.Sprintf("%s/sub[%d]", path, i), forbidden); err != nil {
			return err
		}
	}
	return nil
}

// FunctionAllowlistRule only permits invocations whose function name is in
// the allowlist. This is stricter than contract allowlist and can be used
// to limit what methods are called on allowed contracts.
type FunctionAllowlistRule struct {
	allowed map[string]bool
}

// NewFunctionAllowlistRule creates a rule that only permits invocations
// whose function name is in the allowlist.
func NewFunctionAllowlistRule(allowedFunctions []string) *FunctionAllowlistRule {
	allowed := make(map[string]bool, len(allowedFunctions))
	for _, fn := range allowedFunctions {
		allowed[fn] = true
	}
	return &FunctionAllowlistRule{allowed: allowed}
}

// Name returns the unique identifier for this rule.
func (r *FunctionAllowlistRule) Name() string { return "function_allowlist" }

// Evaluate returns an error if any invocation calls a function not in the allowlist.
func (r *FunctionAllowlistRule) Evaluate(entry xdr.SorobanAuthorizationEntry, credentialsKnown bool) error {
	return r.checkInvocation(entry.RootInvocation, "root")
}

func (r *FunctionAllowlistRule) checkInvocation(inv xdr.SorobanAuthorizedInvocation, path string) error {
	if inv.Function.ContractFn != nil {
		fn := string(inv.Function.ContractFn.FunctionName)
		if !r.allowed[fn] {
			return fmt.Errorf("function %q not in allowlist (at %s)", fn, path)
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocation(sub, fmt.Sprintf("%s/sub[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// AddressBoundRule ensures that the credentials arm is address-bound (V2 or
// delegates). Legacy ADDRESS credentials are refused because they don't bind
// the signer address into the payload, enabling a narrow replay vulnerability.
type AddressBoundRule struct{}

// Name returns the unique identifier for this rule.
func (r *AddressBoundRule) Name() string { return "address_bound" }

// Evaluate returns an error if the credentials are not address-bound.
// This check is only performed when credentialsKnown is true (i.e., for
// ADDRESS_V2 and ADDRESS_WITH_DELEGATES credentials). For legacy preimages
// (type 9), credentialsKnown is false because we cannot distinguish
// SOURCE_ACCOUNT from legacy ADDRESS from the preimage alone.
func (r *AddressBoundRule) Evaluate(entry xdr.SorobanAuthorizationEntry, credentialsKnown bool) error {
	// Only enforce address binding when we can determine the credentials type
	// from the preimage. For legacy preimages (type 9), credentialsKnown is
	// false because we can't distinguish SOURCE_ACCOUNT from legacy ADDRESS.
	if !credentialsKnown {
		return nil
	}
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		return errors.New("legacy ADDRESS credentials used; requires ADDRESS_V2 or ADDRESS_WITH_DELEGATES")
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		// Source account is fine — it's bound by the envelope signature.
		return nil
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		return nil
	default:
		return fmt.Errorf("unknown credentials type %v", entry.Credentials.Type)
	}
}

// Compile-time check for error sentinel
var _ error = (*ErrPolicyRefusal)(nil)
