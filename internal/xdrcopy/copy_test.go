package xdrcopy

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// testAddress derives a deterministic public test account from a label, the
// scheme every soroauth test uses. These keys are public by construction and
// must never be funded on mainnet.
func testAddress(t *testing.T, label string) xdr.ScAddress {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair for %q: %v", label, err)
	}
	accountID, err := xdr.AddressToAccountId(kp.Address())
	if err != nil {
		t.Fatalf("converting %q to account id: %v", kp.Address(), err)
	}
	return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &accountID}
}

// sampleEntry builds an entry that exercises every kind of indirection the XDR
// types use: a union arm behind a pointer (Credentials.AddressV2), a doubly
// indirected slice (ScVal.Vec is **ScVec), a pointer union arm inside the
// invocation (Function.ContractFn), and a recursive slice (SubInvocations).
func sampleEntry(t *testing.T) xdr.SorobanAuthorizationEntry {
	t.Helper()

	sigVec := &xdr.ScVec{{Type: xdr.ScValTypeScvU32, U32: func() *xdr.Uint32 { v := xdr.Uint32(7); return &v }()}}
	signature := xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &sigVec}

	credentials := xdr.SorobanAddressCredentials{
		Address:                   testAddress(t, "soroauth-xdrcopy-account"),
		Nonce:                     xdr.Int64(1234),
		SignatureExpirationLedger: xdr.Uint32(99),
		Signature:                 signature,
	}

	argVal := xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: func() *xdr.ScSymbol { s := xdr.ScSymbol("arg"); return &s }()}

	contractFn := &xdr.InvokeContractArgs{
		ContractAddress: xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &xdr.ContractId{1, 2, 3},
		},
		FunctionName: xdr.ScSymbol("transfer"),
		Args:         []xdr.ScVal{argVal},
	}

	subFn := &xdr.InvokeContractArgs{
		ContractAddress: xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &xdr.ContractId{4, 5, 6},
		},
		FunctionName: xdr.ScSymbol("approve"),
		Args:         []xdr.ScVal{},
	}

	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &credentials,
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type:       xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: contractFn,
			},
			SubInvocations: []xdr.SorobanAuthorizedInvocation{{
				Function: xdr.SorobanAuthorizedFunction{
					Type:       xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: subFn,
				},
			}},
		},
	}
}

func mustMarshal(t *testing.T, v interface{ MarshalBinary() ([]byte, error) }) []byte {
	t.Helper()
	b, err := v.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling %T: %v", v, err)
	}
	return b
}

func TestCopyIsByteIdentical(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) xdr.SorobanAuthorizationEntry
	}{
		{
			name:  "full entry with nested invocations",
			build: sampleEntry,
		},
		{
			name: "source account credentials",
			build: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				e := sampleEntry(t)
				e.Credentials = xdr.SorobanCredentials{
					Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
				}
				return e
			},
		},
		{
			name: "no sub invocations",
			build: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				e := sampleEntry(t)
				e.RootInvocation.SubInvocations = nil
				return e
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.build(t)
			want := mustMarshal(t, original)

			got, err := Copy(original)
			if err != nil {
				t.Fatalf("Copy returned an unexpected error: %v", err)
			}

			if !bytes.Equal(want, mustMarshal(t, got)) {
				t.Errorf("copy is not byte-identical to the original\n want %x\n  got %x", want, mustMarshal(t, got))
			}
		})
	}
}

// TestCopySharesNoMemory is the test that matters: it writes through every
// pointer and slice the copy exposes and proves none of it reaches the
// original. Without a real deep copy, each of these writes would be visible to
// the caller.
func TestCopySharesNoMemory(t *testing.T) {
	original := sampleEntry(t)
	before := mustMarshal(t, original)

	got, err := Copy(original)
	if err != nil {
		t.Fatalf("Copy returned an unexpected error: %v", err)
	}

	if got.Credentials.AddressV2 == original.Credentials.AddressV2 {
		t.Error("copy shares the AddressV2 credentials pointer with the original")
	}
	if got.RootInvocation.Function.ContractFn == original.RootInvocation.Function.ContractFn {
		t.Error("copy shares the ContractFn pointer with the original")
	}

	got.Credentials.AddressV2.Nonce = 4242
	got.Credentials.AddressV2.SignatureExpirationLedger = 1
	(*got.Credentials.AddressV2.Signature.Vec) = &xdr.ScVec{}
	got.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	got.RootInvocation.Function.ContractFn.Args[0] = xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	got.RootInvocation.SubInvocations[0].Function.ContractFn.FunctionName = xdr.ScSymbol("drain_sub")

	after := mustMarshal(t, original)
	if !bytes.Equal(before, after) {
		t.Errorf("mutating the copy changed the original\n before %x\n  after %x", before, after)
	}
}

func TestCopyReturnsErrorForUnmarshalableValue(t *testing.T) {
	// An unset union discriminant has no arm to encode, so the generated
	// EncodeTo refuses it. Copy must surface that rather than hand back a
	// half-built value.
	invalid := xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)}

	got, err := Copy(invalid)
	if err == nil {
		t.Fatalf("Copy succeeded on an invalid union, returning %+v", got)
	}
	if want := "soroauth: xdrcopy: marshal"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Errorf("error %q does not carry the %q prefix", err, want)
	}
	if got != (xdr.SorobanCredentials{}) {
		t.Errorf("Copy returned %+v alongside an error, want the zero value", got)
	}
}
