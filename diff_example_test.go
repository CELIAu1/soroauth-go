package soroauth_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// diffExampleVector is a committed golden vector: its signed entry carries a
// real signature over the vector's expiration ledger, so bumping that ledger
// afterward leaves the signature in place and moves the payload underneath it.
const diffExampleVector = "testdata/vectors/v2_single_testnet.json"

type diffExampleFixture struct {
	ValidUntilLedger uint32 `json:"valid_until_ledger"`
	SignedEntryXDR   string `json:"signed_entry_xdr"`
}

func diffExampleLoad() diffExampleFixture {
	raw, err := os.ReadFile(diffExampleVector)
	if err != nil {
		panic(err)
	}
	var fixture diffExampleFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(err)
	}
	return fixture
}

func diffExampleSignedEntry() (xdr.SorobanAuthorizationEntry, uint32) {
	fixture := diffExampleLoad()
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(fixture.SignedEntryXDR, &entry); err != nil {
		panic(err)
	}
	return entry, fixture.ValidUntilLedger
}

// ExampleDiffEntries compares an entry with a copy whose expiration moved by one
// ledger and whose signature was left exactly as it was.
//
// The report separates the two facts that matter: the payload changed, and the
// signature did not. That combination is the finding this type exists for — the
// entry still reads as signed and no longer verifies. Under CAP-71-01 the
// expiration is inside the signed preimage, so changing it invalidates every
// signature that was not remade against the new value.
func ExampleDiffEntries() {
	signed, validUntil := diffExampleSignedEntry()
	tampered, _ := diffExampleSignedEntry()
	tampered.Credentials.AddressV2.SignatureExpirationLedger = xdr.Uint32(validUntil + 1)

	diff, err := soroauth.DiffEntries(signed, tampered)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("payload changed:", diff.PayloadChanged)
	fmt.Println("signatures changed:", diff.SignaturesChanged)
	fmt.Println("stale signatures:", diff.StaleSignatures)
	for _, change := range diff.Changes {
		fmt.Printf("%s %s %s -> %s\n", change.Kind, change.Path, change.From, change.To)
	}

	// Output:
	// payload changed: true
	// signatures changed: false
	// stale signatures: [credentials]
	// expiration credentials.signatureExpirationLedger 1234567 -> 1234568
}

// ExampleEntryDiff_String renders the same stale-signature case for a terminal.
//
// The summary is the first line, so a reviewer who reads only that still learns
// whether a carried-over signature is now invalid. The changes below it mark
// payload-affecting edits with "!": a changed signature would not carry that
// marker, because a signature is never itself signed over.
func ExampleEntryDiff_String() {
	signed, validUntil := diffExampleSignedEntry()
	tampered, _ := diffExampleSignedEntry()
	tampered.Credentials.AddressV2.SignatureExpirationLedger = xdr.Uint32(validUntil + 1)

	diff, err := soroauth.DiffEntries(signed, tampered)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Print(diff)

	// Output:
	// PAYLOAD CHANGED and 1 signature carried over unchanged: it is no longer valid
	//
	// stale signatures (committed to the old payload):
	//   credentials
	//
	// changes:
	//   ! expiration     credentials.signatureExpirationLedger
	//       1234567 -> 1234568
	//
	//   ! marks a change inside the signed payload
}
