package soroauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func canonicalRoundTripEntry(t *testing.T, encoded string) xdr.SorobanAuthorizationEntry {
	t.Helper()

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		t.Fatalf("decoding fixture entry: %v", err)
	}
	return entry
}

func assertCanonicalRoundTrip(t *testing.T, entry xdr.SorobanAuthorizationEntry) {
	t.Helper()

	before, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding entry before round trip: %v", err)
	}
	document, err := MarshalCanonicalJSON(entry)
	if err != nil {
		t.Fatalf("encoding canonical JSON: %v", err)
	}
	decoded, err := UnmarshalCanonicalJSON(document)
	if err != nil {
		t.Fatalf("decoding canonical JSON: %v", err)
	}
	after, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding entry after round trip: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("XDR changed across the canonical JSON round trip\nbefore: %x\nafter:  %x", before, after)
	}
	again, err := MarshalCanonicalJSON(decoded)
	if err != nil {
		t.Fatalf("re-encoding canonical JSON: %v", err)
	}
	if !bytes.Equal(document, again) {
		t.Fatalf("canonical JSON is not stable across a round trip\nfirst:  %s\nsecond: %s", document, again)
	}
}

func TestCanonicalJSONRoundTripsEveryGoldenVector(t *testing.T) {
	for _, vector := range loadVectors(t) {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			for name, encoded := range map[string]string{
				"unsigned": vector.UnsignedEntryXDR,
				"signed":   vector.SignedEntryXDR,
				"pre_wrap": vector.PreWrapEntryXDR,
			} {
				if encoded == "" {
					continue
				}
				name, encoded := name, encoded
				t.Run(name, func(t *testing.T) {
					assertCanonicalRoundTrip(t, canonicalRoundTripEntry(t, encoded))
				})
			}
		})
	}
}

func TestCanonicalJSONPreservesNilAndEmptyCollections(t *testing.T) {
	entry := canonicalRoundTripEntry(t, loadVectors(t)[0].UnsignedEntryXDR)
	function := &xdr.InvokeContractArgs{
		ContractAddress: entry.RootInvocation.Function.ContractFn.ContractAddress,
		FunctionName:    entry.RootInvocation.Function.ContractFn.FunctionName,
	}
	var absentVec *xdr.ScVec
	nilVec := xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &absentVec}
	emptyVec := xdr.ScVec{}
	emptyVecPointer := &emptyVec
	empty := xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &emptyVecPointer}
	var absentMap *xdr.ScMap
	nilMap := xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &absentMap}
	emptyMap := xdr.ScMap{}
	emptyMapPointer := &emptyMap
	emptyMapValue := xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &emptyMapPointer}
	function.Args = []xdr.ScVal{nilVec, empty, nilMap, emptyMapValue}
	entry.RootInvocation.Function.ContractFn = function

	document, err := MarshalCanonicalJSON(entry)
	if err != nil {
		t.Fatalf("encoding canonical JSON: %v", err)
	}
	decoded, err := UnmarshalCanonicalJSON(document)
	if err != nil {
		t.Fatalf("decoding canonical JSON: %v", err)
	}
	args := decoded.RootInvocation.Function.ContractFn.Args
	if args[0].Vec == nil || *args[0].Vec != nil {
		t.Fatal("nil vector did not survive the round trip")
	}
	if args[1].Vec == nil || *args[1].Vec == nil || len(**args[1].Vec) != 0 {
		t.Fatal("empty vector did not survive the round trip")
	}
	if args[2].Map == nil || *args[2].Map != nil {
		t.Fatal("nil map did not survive the round trip")
	}
	if args[3].Map == nil || *args[3].Map == nil || len(**args[3].Map) != 0 {
		t.Fatal("empty map did not survive the round trip")
	}
	assertCanonicalRoundTrip(t, entry)
}

func TestCanonicalJSONRejectsInvalidDocuments(t *testing.T) {
	var entry xdr.SorobanAuthorizationEntry
	for _, vector := range loadVectors(t) {
		if vector.Name == "v2_single_testnet" {
			entry = canonicalRoundTripEntry(t, vector.UnsignedEntryXDR)
			break
		}
	}
	if entry.RootInvocation.Function.ContractFn == nil {
		t.Fatal("v2_single_testnet fixture is missing")
	}
	document, err := MarshalCanonicalJSON(entry)
	if err != nil {
		t.Fatalf("encoding baseline document: %v", err)
	}

	tests := []struct {
		name     string
		document string
		want     string
	}{
		{name: "unknown field", document: replaceJSON(t, document, `"schema_version":1`, `"schema_version":1,"unknown":true`), want: "unknown field"},
		{name: "duplicate key", document: replaceJSON(t, document, `"schema_version":1`, `"schema_version":1,"schema_version":1`), want: "duplicate"},
		{name: "trailing data", document: string(document) + `{}`, want: "trailing"},
		{name: "wrong version", document: replaceJSON(t, document, `"schema_version":1`, `"schema_version":2`), want: "unsupported schema_version"},
		{name: "unknown credential type", document: replaceJSON(t, document, `"type":"address_v2"`, `"type":"future_arm"`), want: "unknown credentials type"},
		{name: "missing invocation", document: `{"schema_version":1,"credentials":{"type":"source_account"},"root_invocation":{"function":{"type":"contract_fn"},"sub_invocations":[]}}`, want: "contract_fn function is missing"},
		{name: "negative unsigned high word", document: replaceJSON(t, document, `{"type":"i32","i32":-7}`, `{"type":"u128","u128":{"hi":"-1","lo":"0"}}`), want: "not a canonical uint64"},
		{name: "extra ScVal field", document: replaceJSON(t, document, `{"type":"u32","u32":7}`, `{"type":"u32","u32":7,"bool":true}`), want: "carries"},
		{name: "invalid base64", document: replaceJSON(t, document, `"bytes":"c29yb2F1dGg="`, `"bytes":"!!!!"`), want: "base64"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			decoded, err := UnmarshalCanonicalJSON([]byte(test.document))
			if err == nil {
				t.Fatalf("accepted invalid document, decoded %+v", decoded)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not contain %q", err, test.want)
			}
		})
	}
}

func TestCanonicalJSONRejectsOversizeInput(t *testing.T) {
	document := make([]byte, MaxCanonicalJSONBytes+1)
	for i := range document {
		document[i] = ' '
	}
	_, err := UnmarshalCanonicalJSON(document)
	if !errors.Is(err, ErrDecodeLimit) {
		t.Fatalf("error = %v, want ErrDecodeLimit", err)
	}
}

func replaceJSON(t *testing.T, document []byte, old, replacement string) string {
	t.Helper()

	if !bytes.Contains(document, []byte(old)) {
		t.Fatalf("baseline document does not contain %q:\n%s", old, document)
	}
	return strings.Replace(string(document), old, replacement, 1)
}

func canonicalFuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()

	var seeds [][]byte
	for _, vector := range loadVectors(tb) {
		for _, encoded := range []string{vector.UnsignedEntryXDR, vector.SignedEntryXDR, vector.PreWrapEntryXDR} {
			if encoded == "" {
				continue
			}
			var entry xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
				tb.Fatalf("decoding fuzz seed: %v", err)
			}
			raw, err := entry.MarshalBinary()
			if err != nil {
				tb.Fatalf("encoding fuzz seed: %v", err)
			}
			seeds = append(seeds, raw)
		}
	}
	return seeds
}

func FuzzCanonicalJSON(f *testing.F) {
	for _, seed := range canonicalFuzzSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var entry xdr.SorobanAuthorizationEntry
		if err := entry.UnmarshalBinary(data); err != nil {
			return
		}
		document, err := MarshalCanonicalJSON(entry)
		if err != nil {
			return
		}
		decoded, err := UnmarshalCanonicalJSON(document)
		if err != nil {
			t.Fatalf("valid entry produced a document it cannot decode: %v", err)
		}
		before, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("encoding input entry: %v", err)
		}
		after, err := decoded.MarshalBinary()
		if err != nil {
			t.Fatalf("encoding decoded entry: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("XDR changed across the canonical JSON round trip\nbefore: %x\nafter:  %x", before, after)
		}
	})
}

func TestCanonicalJSONDocumentShape(t *testing.T) {
	entry := canonicalRoundTripEntry(t, loadVectors(t)[0].UnsignedEntryXDR)
	document, err := MarshalCanonicalJSON(entry)
	if err != nil {
		t.Fatalf("encoding canonical JSON: %v", err)
	}
	var shape struct {
		SchemaVersion int `json:"schema_version"`
		Credentials   struct {
			Type string `json:"type"`
		} `json:"credentials"`
		RootInvocation json.RawMessage `json:"root_invocation"`
	}
	if err := json.Unmarshal(document, &shape); err != nil {
		t.Fatalf("decoding document shape: %v", err)
	}
	if shape.SchemaVersion != CanonicalJSONSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", shape.SchemaVersion, CanonicalJSONSchemaVersion)
	}
	if shape.Credentials.Type == "" {
		t.Fatal("credentials.type is empty")
	}
	if len(shape.RootInvocation) == 0 {
		t.Fatal("root_invocation is empty")
	}
}

func canonicalValue[T any](value T) *T {
	return &value
}

func TestCanonicalJSONRoundTripsEveryScValArm(t *testing.T) {
	var encoded string
	for _, vector := range loadVectors(t) {
		if vector.Name == "v2_single_testnet" {
			encoded = vector.UnsignedEntryXDR
			break
		}
	}
	if encoded == "" {
		t.Fatal("v2_single_testnet fixture is missing")
	}
	entry := canonicalRoundTripEntry(t, encoded)
	if entry.RootInvocation.Function.ContractFn == nil {
		t.Fatal("fixture is not a contract call")
	}
	credentials := entry.Credentials.AddressV2
	if credentials == nil {
		credentials = entry.Credentials.Address
	}
	if credentials == nil {
		t.Fatal("fixture has no address credentials")
	}
	account := credentials.Address
	contract := entry.RootInvocation.Function.ContractFn.ContractAddress

	wasmHash := xdr.Hash{1, 2, 3}
	storage := xdr.ScMap{{Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: canonicalValue(xdr.ScSymbol("key"))}, Val: xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: canonicalValue(xdr.Uint32(1))}}}
	vector := xdr.ScVec{
		{Type: xdr.ScValTypeScvVoid},
		{Type: xdr.ScValTypeScvString, Str: canonicalValue(xdr.ScString("nested"))},
	}
	mapValue := xdr.ScMap{{Key: xdr.ScVal{Type: xdr.ScValTypeScvBool, B: canonicalValue(true)}, Val: xdr.ScVal{Type: xdr.ScValTypeScvI32, I32: canonicalValue(xdr.Int32(-3))}}}
	args := []xdr.ScVal{
		{Type: xdr.ScValTypeScvVoid},
		{Type: xdr.ScValTypeScvBool, B: canonicalValue(true)},
		{Type: xdr.ScValTypeScvU32, U32: canonicalValue(xdr.Uint32(7))},
		{Type: xdr.ScValTypeScvI32, I32: canonicalValue(xdr.Int32(-7))},
		{Type: xdr.ScValTypeScvU64, U64: canonicalValue(xdr.Uint64(1 << 40))},
		{Type: xdr.ScValTypeScvI64, I64: canonicalValue(xdr.Int64(-1 << 40))},
		{Type: xdr.ScValTypeScvTimepoint, Timepoint: canonicalValue(xdr.TimePoint(123))},
		{Type: xdr.ScValTypeScvDuration, Duration: canonicalValue(xdr.Duration(456))},
		{Type: xdr.ScValTypeScvU128, U128: &xdr.UInt128Parts{Hi: 1, Lo: 2}},
		{Type: xdr.ScValTypeScvI128, I128: &xdr.Int128Parts{Hi: -1, Lo: 2}},
		{Type: xdr.ScValTypeScvU256, U256: &xdr.UInt256Parts{HiHi: 1, HiLo: 2, LoHi: 3, LoLo: 4}},
		{Type: xdr.ScValTypeScvI256, I256: &xdr.Int256Parts{HiHi: -1, HiLo: 2, LoHi: 3, LoLo: 4}},
		{Type: xdr.ScValTypeScvBytes, Bytes: canonicalValue(xdr.ScBytes([]byte{0, 1, 2}))},
		{Type: xdr.ScValTypeScvString, Str: canonicalValue(xdr.ScString("hello"))},
		{Type: xdr.ScValTypeScvString, Str: canonicalValue(xdr.ScString(string([]byte{0xff, 0xfe})))},
		{Type: xdr.ScValTypeScvSymbol, Sym: canonicalValue(xdr.ScSymbol("symbol"))},
		{Type: xdr.ScValTypeScvVec, Vec: canonicalValue(&vector)},
		{Type: xdr.ScValTypeScvMap, Map: canonicalValue(&mapValue)},
		{Type: xdr.ScValTypeScvAddress, Address: canonicalValue(account)},
		{Type: xdr.ScValTypeScvAddress, Address: canonicalValue(contract)},
		{Type: xdr.ScValTypeScvContractInstance, Instance: &xdr.ScContractInstance{
			Executable: xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableWasm, WasmHash: &wasmHash},
			Storage:    &storage,
		}},
		{Type: xdr.ScValTypeScvContractInstance, Instance: &xdr.ScContractInstance{
			Executable: xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableStellarAsset},
		}},
		{Type: xdr.ScValTypeScvContractInstance, Instance: &xdr.ScContractInstance{
			Executable: xdr.ContractExecutable{
				Type:        xdr.ContractExecutableTypeContractExecutableExternalRef,
				ExternalRef: &xdr.ContractExecutableExternalRef{ExecutableOwner: account, Tag: xdr.ScString("ref")},
			},
		}},
		{Type: xdr.ScValTypeScvLedgerKeyContractInstance},
		{Type: xdr.ScValTypeScvExecutableTag, ExecutableTag: canonicalValue(xdr.ScString("tag"))},
		{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceContract, ContractCode: canonicalValue(xdr.Uint32(9))}},
		{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceAuth, Code: canonicalValue(xdr.ScErrorCodeScecInvalidAction)}},
		{Type: xdr.ScValTypeScvLedgerKeyNonce, NonceKey: &xdr.ScNonceKey{Nonce: -5}},
	}
	function := *entry.RootInvocation.Function.ContractFn
	function.Args = args
	entry.RootInvocation.Function.ContractFn = &function

	assertCanonicalRoundTrip(t, entry)
}
