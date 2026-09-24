package soroauth

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// benchKeypair derives a deterministic public test keypair from a label.
func benchKeypair(b *testing.B, label string) *keypair.Full {
	b.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		b.Fatalf("deriving keypair for %q: %v", label, err)
	}
	return kp
}

// benchContractAddress derives a deterministic C… address from a label.
func benchContractAddress(b *testing.B, label string) string {
	b.Helper()
	sum := sha256.Sum256([]byte(label))
	address, err := strkey.Encode(strkey.VersionByteContract, sum[:])
	if err != nil {
		b.Fatalf("encoding contract address for %q: %v", label, err)
	}
	return address
}

// benchEntry returns a deterministic V2 address entry for signing benchmarks.
func benchEntry(b *testing.B) xdr.SorobanAuthorizationEntry {
	b.Helper()
	addr, err := ParseAddress(benchKeypair(b, "soroauth-bench-signer").Address())
	if err != nil {
		b.Fatalf("parsing the bench signer address: %v", err)
	}
	contract, err := ParseAddress(benchContractAddress(b, "soroauth-bench-contract"))
	if err != nil {
		b.Fatalf("parsing the bench contract address: %v", err)
	}
	amount := xdr.Int64(100)
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   addr,
				Nonce:     42,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: &amount}},
				},
			},
		},
	}
}

// BenchmarkAuthorizeEntry measures the full signing path: context check, deep
// copy, preimage, payload hash, signer.Sign, and writing the signature.
func BenchmarkAuthorizeEntry(b *testing.B) {
	entry := benchEntry(b)
	signer := NewEd25519Signer(benchKeypair(b, "soroauth-bench-signer"))
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthorizeAll measures the batch signing path over one entry.
func BenchmarkAuthorizeAll(b *testing.B) {
	entry := benchEntry(b)
	signer := NewEd25519Signer(benchKeypair(b, "soroauth-bench-signer"))
	ctx := context.Background()
	entries := []xdr.SorobanAuthorizationEntry{entry}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeAll(ctx, entries, []Signer{signer}, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthorizeInvocation measures building and signing from scratch.
func BenchmarkAuthorizeInvocation(b *testing.B) {
	signer := NewEd25519Signer(benchKeypair(b, "soroauth-bench-signer"))
	ctx := context.Background()
	params := AuthorizeInvocationParams{
		Signer:            signer,
		Invocation:        benchEntry(b).RootInvocation,
		ValidUntilLedger:  testValidUntilLedger,
		NetworkPassphrase: network.TestNetworkPassphrase,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeInvocation(ctx, params); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPreimage measures HashIdPreimage construction alone.
func BenchmarkPreimage(b *testing.B) {
	entry := benchEntry(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPayload measures SHA-256 over the marshaled preimage alone.
func BenchmarkPayload(b *testing.B) {
	entry := benchEntry(b)
	pre, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Payload(pre); err != nil {
			b.Fatal(err)
		}
	}
}
