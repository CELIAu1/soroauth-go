package soroauth_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// verifyExampleVector is a committed golden vector with a classic-account
// signature: the signed entry carries the exact shape the host decodes as an
// account signature, and the unsigned entry carries the empty vector simulation
// returns.
const verifyExampleVector = "testdata/vectors/v2_single_testnet.json"

type verifyExampleFixture struct {
	NetworkPassphrase string `json:"network_passphrase"`
	UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
	SignedEntryXDR    string `json:"signed_entry_xdr"`
}

func verifyExampleLoad() verifyExampleFixture {
	raw, err := os.ReadFile(verifyExampleVector)
	if err != nil {
		panic(err)
	}
	var fixture verifyExampleFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(err)
	}
	return fixture
}

func verifyExampleDecode(encoded string) xdr.SorobanAuthorizationEntry {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		panic(err)
	}
	return entry
}

// ExampleVerifyEntry checks the signed entry from a committed golden vector.
//
// The payload is rebuilt from the entry itself, including the expiration ledger
// stored on it, so verification asks whether the entry as it stands commits to
// the signature it carries. It does not prove the key is a signer of the
// account or that the account's threshold is met; those are ledger state this
// offline check cannot see.
func ExampleVerifyEntry() {
	fixture := verifyExampleLoad()
	entry := verifyExampleDecode(fixture.SignedEntryXDR)

	report, err := soroauth.VerifyEntry(entry, fixture.NetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("credential type:", report.CredentialType)
	for _, node := range report.Nodes {
		fmt.Printf("%s %s\n", node.Address, node.Verdict)
	}
	fmt.Println("verified:", report.Verified())

	// Output:
	// credential type: address_v2
	// GC33NWBJFXQSQMD3AMHTFEFT36IH5ZBG24L5RZMQGKO2SPBTVB74VZI5 verified
	// verified: true
}

// ExampleVerifyEntry_unsigned checks the entry simulation returned, before any
// signature was written. Its signature field is an empty vector, which is the
// ordinary unsigned placeholder, so the verdict is unsigned rather than invalid.
//
// This engine reports an unsigned node instead of failing it because CAP-71-01
// allows a delegates entry to leave its top-level node Void when only delegates
// authenticate. Whether an unsigned node is acceptable is the account's policy;
// Verified() is false either way, so a caller that requires every node to check
// out is not misled.
func ExampleVerifyEntry_unsigned() {
	fixture := verifyExampleLoad()
	entry := verifyExampleDecode(fixture.UnsignedEntryXDR)

	report, err := soroauth.VerifyEntry(entry, fixture.NetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	node := report.Nodes[0]
	fmt.Println("verdict:", node.Verdict)
	fmt.Println("reason:", node.Reason)
	fmt.Println("verified:", report.Verified())

	// Output:
	// verdict: unsigned
	// reason: the node carries no signature (Void or an empty vector)
	// verified: false
}

// ExampleVerifyEntry_invalid flips one byte of the signature on the signed
// golden entry, in code, and verifies the result.
//
// This is the difference the fourth verdict exists to preserve: a signature is
// present and in the built-in shape, but it does not verify over the entry's
// payload. Reporting that as "unsigned" would make a tampered entry read the
// same as one that was simply never signed.
func ExampleVerifyEntry_invalid() {
	fixture := verifyExampleLoad()
	entry := verifyExampleDecode(fixture.SignedEntryXDR)

	vec, ok := entry.Credentials.AddressV2.Signature.GetVec()
	if !ok {
		fmt.Println("signature is not a vector")
		return
	}
	m, ok := (*vec)[0].GetMap()
	if !ok {
		fmt.Println("signature element is not a map")
		return
	}
	// The map is {public_key, signature} in key order; the second value is the
	// 64-byte ed25519 signature.
	(*(*m)[1].Val.Bytes)[0] ^= 0xff

	report, err := soroauth.VerifyEntry(entry, fixture.NetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	node := report.Nodes[0]
	fmt.Println("verdict:", node.Verdict)
	fmt.Println("reason:", node.Reason)
	fmt.Println("verified:", report.Verified())

	// Output:
	// verdict: invalid
	// reason: the stored signature does not verify over the payload the entry commits to
	// verified: false
}

// ExampleVerifyEntry_cannotCheck points the credential node at a contract
// address.
//
// cannot_check is not a failure: a contract's __check_auth defines its own
// signature shape, so no offline engine can decide whether the value is valid.
// It is also not a pass — Verified() is false, because this library never
// reports a node it did not check as verified. Only the contract can answer.
func ExampleVerifyEntry_cannotCheck() {
	fixture := verifyExampleLoad()
	entry := verifyExampleDecode(fixture.SignedEntryXDR)

	// The root invocation already names a contract, so reuse it as the node's
	// address. This is built from the committed vector, not hand-edited XDR.
	entry.Credentials.AddressV2.Address = entry.RootInvocation.Function.ContractFn.ContractAddress

	report, err := soroauth.VerifyEntry(entry, fixture.NetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	node := report.Nodes[0]
	fmt.Println("address:", node.Address)
	fmt.Println("verdict:", node.Verdict)
	fmt.Println("reason:", node.Reason)
	fmt.Println("verified:", report.Verified())

	// Output:
	// address: CA2GWZB4O7LIPISULUNERN4GCUNMVZP7VIHLLL3A6XDPHI7QD6VNCMEV
	// verdict: cannot_check
	// reason: the node addresses a C… contract; only the contract's __check_auth defines whether its signature is valid, so this cannot be checked offline
	// verified: false
}
