package soroauth_test

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Addresses used by the analyzer examples. They are fixed public test values
// so the output is reproducible; they hold nothing and are not funded.
const (
	riskExampleWallet   = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"
	riskExampleContract = "CA2GWZB4O7LIPISULUNERN4GCUNMVZP7VIHLLL3A6XDPHI7QD6VNCMEV"
)

// riskExampleEntry builds a structurally ordinary V2 entry: an expiration in
// the future, no delegates and a transfer call on a contract.
func riskExampleEntry() xdr.SorobanAuthorizationEntry {
	address, err := soroauth.ParseAddress(riskExampleWallet)
	if err != nil {
		panic(err)
	}
	contract, err := soroauth.ParseAddress(riskExampleContract)
	if err != nil {
		panic(err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     1,
				SignatureExpirationLedger: 5_000_000,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}
}

// ExampleAnalyze_clean runs the analyzer over an entry that trips none of its
// heuristics.
//
// No findings does not mean the entry is safe. Analyze is a structural check:
// it does not decode contract arguments, verify contract behavior or evaluate
// the account's policy. An empty result means only that the patterns it looks
// for are absent; see docs/analyzer-heuristics.md for what it cannot see.
func ExampleAnalyze_clean() {
	findings, err := soroauth.Analyze(riskExampleEntry(), nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("findings:", len(findings))

	// Output:
	// findings: 0
}

// ExampleAnalyze_findings shows what a finding looks like. The entry is the
// same clean one with its expiration set to zero, which the host treats as
// already expired; Analyze reports that as a critical structural failure before
// anything is signed.
//
// A finding is a prompt to review, not a proof that the entry will fail: the
// analyzer is heuristic, and the reverse is true as well — no findings is not a
// safety verdict.
func ExampleAnalyze_findings() {
	entry := riskExampleEntry()
	entry.Credentials.AddressV2.SignatureExpirationLedger = 0

	findings, err := soroauth.Analyze(entry, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for _, finding := range findings {
		fmt.Printf("%s %s: %s\n", finding.Severity, finding.Code, finding.Title)
	}

	// Output:
	// critical EXPIRATION_ZERO: Signature expiration is zero (already expired)
}
