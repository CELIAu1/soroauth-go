package soroauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// CanonicalJSONSchemaVersion is the version of the canonical JSON document
// MarshalCanonicalJSON emits and UnmarshalCanonicalJSON accepts.
//
// The version is part of every document. A later change to the field names or
// value shapes is therefore detectable by a reader instead of being silently
// interpreted as the old schema.
const CanonicalJSONSchemaVersion = 1

// MaxCanonicalJSONBytes is the maximum size of a canonical JSON document
// UnmarshalCanonicalJSON accepts.
//
// Canonical JSON is another untrusted-input surface, and it expands XDR values
// (base64, decimal strings, field names) rather than shrinking them. The bound
// is deliberately larger than MaxDecodeInputBytes while still refusing a
// document that could make the decoder allocate without limit.
const MaxCanonicalJSONBytes = 8 << 20

type canonicalEntry struct {
	SchemaVersion  int                 `json:"schema_version"`
	Credentials    canonicalCredential `json:"credentials"`
	RootInvocation canonicalInvocation `json:"root_invocation"`
}

type canonicalCredential struct {
	Type                      string               `json:"type"`
	Address                   *canonicalAddress    `json:"address,omitempty"`
	Nonce                     *string              `json:"nonce,omitempty"`
	SignatureExpirationLedger *uint32              `json:"signature_expiration_ledger,omitempty"`
	Signature                 *canonicalScVal      `json:"signature,omitempty"`
	Delegates                 *[]canonicalDelegate `json:"delegates,omitempty"`
}

type canonicalDelegate struct {
	Address   canonicalAddress    `json:"address"`
	Signature canonicalScVal      `json:"signature"`
	Nested    []canonicalDelegate `json:"nested"`
}

type canonicalInvocation struct {
	Function       canonicalFunction     `json:"function"`
	SubInvocations []canonicalInvocation `json:"sub_invocations"`
}

type canonicalFunction struct {
	Type               string               `json:"type"`
	ContractAddress    *canonicalAddress    `json:"contract_address,omitempty"`
	FunctionName       *canonicalText       `json:"function_name,omitempty"`
	Args               *[]canonicalScVal    `json:"args,omitempty"`
	ContractIDPreimage *canonicalPreimage   `json:"contract_id_preimage,omitempty"`
	Executable         *canonicalExecutable `json:"executable,omitempty"`
	ConstructorArgs    *[]canonicalScVal    `json:"constructor_args,omitempty"`
}

type canonicalPreimage struct {
	Type    string            `json:"type"`
	Address *canonicalAddress `json:"address,omitempty"`
	Salt    *string           `json:"salt,omitempty"`
	XDR     string            `json:"xdr,omitempty"`
}

type canonicalExecutable struct {
	Type     string            `json:"type"`
	WasmHash *string           `json:"wasm_hash,omitempty"`
	Owner    *canonicalAddress `json:"owner,omitempty"`
	Tag      *canonicalText    `json:"tag,omitempty"`
}

type canonicalAddress struct {
	Type     string `json:"type"`
	Account  string `json:"account,omitempty"`
	Contract string `json:"contract,omitempty"`
	XDR      string `json:"xdr,omitempty"`
}

type canonicalText struct {
	UTF8   *string `json:"utf8,omitempty"`
	Base64 *string `json:"base64,omitempty"`
}

type canonicalParts128 struct {
	Hi string `json:"hi"`
	Lo string `json:"lo"`
}

type canonicalParts256 struct {
	HiHi string `json:"hi_hi"`
	HiLo string `json:"hi_lo"`
	LoHi string `json:"lo_hi"`
	LoLo string `json:"lo_lo"`
}

type canonicalScVal struct {
	Type          string               `json:"type"`
	Bool          *bool                `json:"bool,omitempty"`
	U32           *uint32              `json:"u32,omitempty"`
	I32           *int32               `json:"i32,omitempty"`
	U64           *string              `json:"u64,omitempty"`
	I64           *string              `json:"i64,omitempty"`
	Timepoint     *string              `json:"timepoint,omitempty"`
	Duration      *string              `json:"duration,omitempty"`
	U128          *canonicalParts128   `json:"u128,omitempty"`
	I128          *canonicalParts128   `json:"i128,omitempty"`
	U256          *canonicalParts256   `json:"u256,omitempty"`
	I256          *canonicalParts256   `json:"i256,omitempty"`
	Bytes         *string              `json:"bytes,omitempty"`
	String        *canonicalText       `json:"string,omitempty"`
	Symbol        *canonicalText       `json:"symbol,omitempty"`
	Vec           *[]canonicalScVal    `json:"vec,omitempty"`
	Map           *[]canonicalMapEntry `json:"map,omitempty"`
	Nil           bool                 `json:"nil,omitempty"`
	Address       *canonicalAddress    `json:"address,omitempty"`
	Instance      *canonicalInstance   `json:"contract_instance,omitempty"`
	XDR           string               `json:"xdr,omitempty"`
	ExecutableTag *canonicalText       `json:"executable_tag,omitempty"`
}

type canonicalMapEntry struct {
	Key canonicalScVal `json:"key"`
	Val canonicalScVal `json:"val"`
}

type canonicalInstance struct {
	Executable canonicalExecutable  `json:"executable"`
	Storage    *[]canonicalMapEntry `json:"storage,omitempty"`
}

// MarshalCanonicalJSON renders an authorization entry as canonical JSON.
//
// The encoding is exact: every field of the XDR value has a representation,
// including nil versus empty vectors and maps, invalid UTF-8 strings (as
// base64), and values with no stable strkey spelling (as bounded XDR). It is
// intended for review, diffing, storage and templating, not as a replacement
// for XDR: callers that need the protocol bytes should use MarshalBinary.
//
// The encoder refuses an entry it cannot represent exactly rather than dropping
// a field, and refuses an entry whose XDR encoding is invalid. The output has a
// fixed field order, so two encodings of the same bytes are byte-identical.
func MarshalCanonicalJSON(entry xdr.SorobanAuthorizationEntry) ([]byte, error) {
	if _, err := safeMarshalXDR(entry); err != nil {
		return nil, fmt.Errorf("soroauth: canonical json: entry does not encode: %w", err)
	}

	credentials, err := encodeCanonicalCredentials(entry.Credentials, 0)
	if err != nil {
		return nil, fmt.Errorf("soroauth: canonical json: credentials: %w", err)
	}
	invocation, err := encodeCanonicalInvocation(entry.RootInvocation, 0)
	if err != nil {
		return nil, fmt.Errorf("soroauth: canonical json: root invocation: %w", err)
	}

	document := canonicalEntry{
		SchemaVersion:  CanonicalJSONSchemaVersion,
		Credentials:    credentials,
		RootInvocation: invocation,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("soroauth: canonical json: %w", err)
	}
	if len(encoded) > MaxCanonicalJSONBytes {
		return nil, fmt.Errorf("soroauth: canonical json: %d bytes exceeds the %d-byte limit: %w",
			len(encoded), MaxCanonicalJSONBytes, ErrDecodeLimit)
	}
	return encoded, nil
}

// UnmarshalCanonicalJSON parses a canonical JSON document into an
// authorization entry.
//
// Parsing is strict: unknown fields, duplicate object keys, trailing data,
// unsupported schema versions and values that do not name a valid XDR value are
// refused. The result is validated by encoding it back to XDR, so a document
// that parses but cannot be represented on the wire is never returned.
//
// The decoder applies MaxCanonicalJSONBytes and MaxDecodeDepth; a refusal for
// either bound wraps ErrDecodeLimit.
func UnmarshalCanonicalJSON(data []byte) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry

	if len(data) > MaxCanonicalJSONBytes {
		return entry, fmt.Errorf("soroauth: canonical json: %d bytes exceeds the %d-byte limit: %w",
			len(data), MaxCanonicalJSONBytes, ErrDecodeLimit)
	}
	if !utf8.Valid(data) {
		return entry, fmt.Errorf("soroauth: canonical json: input is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return entry, fmt.Errorf("soroauth: canonical json: %w", err)
	}

	var document canonicalEntry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return entry, fmt.Errorf("soroauth: canonical json: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return entry, fmt.Errorf("soroauth: canonical json: %w", err)
	}
	if document.SchemaVersion != CanonicalJSONSchemaVersion {
		return entry, fmt.Errorf("soroauth: canonical json: unsupported schema_version %d, want %d",
			document.SchemaVersion, CanonicalJSONSchemaVersion)
	}

	credentials, err := decodeCanonicalCredentials(document.Credentials, 0)
	if err != nil {
		return entry, fmt.Errorf("soroauth: canonical json: credentials: %w", err)
	}
	invocation, err := decodeCanonicalInvocation(document.RootInvocation, 0)
	if err != nil {
		return entry, fmt.Errorf("soroauth: canonical json: root invocation: %w", err)
	}

	entry = xdr.SorobanAuthorizationEntry{Credentials: credentials, RootInvocation: invocation}
	if _, err := safeMarshalXDR(entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: canonical json: entry does not encode: %w", err)
	}
	return entry, nil
}

func encodeCanonicalCredentials(credentials xdr.SorobanCredentials, depth int) (canonicalCredential, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return canonicalCredential{}, err
	}

	switch credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return canonicalCredential{Type: CredentialTypeSourceAccount}, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		arm := credentials.Address
		name := CredentialTypeAddress
		if credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
			arm = credentials.AddressV2
			name = CredentialTypeAddressV2
		}
		if arm == nil {
			return canonicalCredential{}, fmt.Errorf("%s arm has no address credentials", name)
		}
		return encodeCanonicalAddressCredentials(name, *arm, depth)

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if credentials.AddressWithDelegates == nil {
			return canonicalCredential{}, fmt.Errorf("address_with_delegates arm has no credentials")
		}
		delegates := credentials.AddressWithDelegates
		encoded, err := encodeCanonicalAddressCredentials(CredentialTypeAddressWithDelegates,
			delegates.AddressCredentials, depth)
		if err != nil {
			return canonicalCredential{}, err
		}
		if err := checkTraversalDepth(depth + 1); err != nil {
			return canonicalCredential{}, err
		}
		nodes, err := encodeCanonicalDelegates(delegates.Delegates, depth+1)
		if err != nil {
			return canonicalCredential{}, err
		}
		encoded.Delegates = &nodes
		return encoded, nil

	default:
		return canonicalCredential{}, fmt.Errorf("unknown credentials type %d: %w",
			credentials.Type, ErrUnsupportedCredentials)
	}
}

func encodeCanonicalAddressCredentials(name string, credentials xdr.SorobanAddressCredentials, depth int) (canonicalCredential, error) {
	address, err := encodeCanonicalAddress(credentials.Address)
	if err != nil {
		return canonicalCredential{}, err
	}
	nonce := strconv.FormatInt(int64(credentials.Nonce), 10)
	expiration := uint32(credentials.SignatureExpirationLedger)
	signature, err := encodeCanonicalScVal(credentials.Signature, depth+1)
	if err != nil {
		return canonicalCredential{}, err
	}
	return canonicalCredential{
		Type:                      name,
		Address:                   &address,
		Nonce:                     &nonce,
		SignatureExpirationLedger: &expiration,
		Signature:                 &signature,
	}, nil
}

func encodeCanonicalDelegates(delegates []xdr.SorobanDelegateSignature, depth int) ([]canonicalDelegate, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return nil, err
	}
	out := make([]canonicalDelegate, 0, len(delegates))
	for i, delegate := range delegates {
		address, err := encodeCanonicalAddress(delegate.Address)
		if err != nil {
			return nil, fmt.Errorf("delegate %d address: %w", i, err)
		}
		signature, err := encodeCanonicalScVal(delegate.Signature, depth+1)
		if err != nil {
			return nil, fmt.Errorf("delegate %d signature: %w", i, err)
		}
		nested, err := encodeCanonicalDelegates(delegate.NestedDelegates, depth+1)
		if err != nil {
			return nil, fmt.Errorf("delegate %d: %w", i, err)
		}
		out = append(out, canonicalDelegate{Address: address, Signature: signature, Nested: nested})
	}
	return out, nil
}

func encodeCanonicalInvocation(invocation xdr.SorobanAuthorizedInvocation, depth int) (canonicalInvocation, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return canonicalInvocation{}, err
	}
	function, err := encodeCanonicalFunction(invocation.Function, depth+1)
	if err != nil {
		return canonicalInvocation{}, err
	}
	subs := make([]canonicalInvocation, 0, len(invocation.SubInvocations))
	for i, sub := range invocation.SubInvocations {
		encoded, err := encodeCanonicalInvocation(sub, depth+1)
		if err != nil {
			return canonicalInvocation{}, fmt.Errorf("sub-invocation %d: %w", i, err)
		}
		subs = append(subs, encoded)
	}
	return canonicalInvocation{Function: function, SubInvocations: subs}, nil
}

func encodeCanonicalFunction(function xdr.SorobanAuthorizedFunction, depth int) (canonicalFunction, error) {
	switch function.Type {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		if function.ContractFn == nil {
			return canonicalFunction{}, fmt.Errorf("contract_fn arm has no invocation")
		}
		contract := function.ContractFn
		address, err := encodeCanonicalAddress(contract.ContractAddress)
		if err != nil {
			return canonicalFunction{}, err
		}
		name := encodeCanonicalText(string(contract.FunctionName))
		args, err := encodeCanonicalScVals(contract.Args, depth+1)
		if err != nil {
			return canonicalFunction{}, err
		}
		return canonicalFunction{
			Type:            "contract_fn",
			ContractAddress: &address,
			FunctionName:    &name,
			Args:            &args,
		}, nil

	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		if function.CreateContractHostFn == nil {
			return canonicalFunction{}, fmt.Errorf("create_contract_host_fn arm has no invocation")
		}
		preimage, err := encodeCanonicalPreimage(function.CreateContractHostFn.ContractIdPreimage)
		if err != nil {
			return canonicalFunction{}, err
		}
		executable, err := encodeCanonicalExecutable(function.CreateContractHostFn.Executable)
		if err != nil {
			return canonicalFunction{}, err
		}
		return canonicalFunction{
			Type:               "create_contract_host_fn",
			ContractIDPreimage: &preimage,
			Executable:         &executable,
		}, nil

	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		if function.CreateContractV2HostFn == nil {
			return canonicalFunction{}, fmt.Errorf("create_contract_v2_host_fn arm has no invocation")
		}
		preimage, err := encodeCanonicalPreimage(function.CreateContractV2HostFn.ContractIdPreimage)
		if err != nil {
			return canonicalFunction{}, err
		}
		executable, err := encodeCanonicalExecutable(function.CreateContractV2HostFn.Executable)
		if err != nil {
			return canonicalFunction{}, err
		}
		args, err := encodeCanonicalScVals(function.CreateContractV2HostFn.ConstructorArgs, depth+1)
		if err != nil {
			return canonicalFunction{}, err
		}
		return canonicalFunction{
			Type:               "create_contract_v2_host_fn",
			ContractIDPreimage: &preimage,
			Executable:         &executable,
			ConstructorArgs:    &args,
		}, nil

	default:
		return canonicalFunction{}, fmt.Errorf("unknown authorized function type %d", function.Type)
	}
}

func encodeCanonicalPreimage(preimage xdr.ContractIdPreimage) (canonicalPreimage, error) {
	switch preimage.Type {
	case xdr.ContractIdPreimageTypeContractIdPreimageFromAddress:
		if preimage.FromAddress == nil {
			return canonicalPreimage{}, fmt.Errorf("from_address arm has no preimage")
		}
		address, err := encodeCanonicalAddress(preimage.FromAddress.Address)
		if err != nil {
			return canonicalPreimage{}, err
		}
		salt := hex.EncodeToString(preimage.FromAddress.Salt[:])
		return canonicalPreimage{Type: "from_address", Address: &address, Salt: &salt}, nil
	case xdr.ContractIdPreimageTypeContractIdPreimageFromAsset:
		if preimage.FromAsset == nil {
			return canonicalPreimage{}, fmt.Errorf("from_asset arm has no asset")
		}
		encoded, err := safeMarshalBase64(preimage.FromAsset)
		if err != nil {
			return canonicalPreimage{}, fmt.Errorf("from_asset: %w", err)
		}
		return canonicalPreimage{Type: "from_asset", XDR: encoded}, nil
	default:
		return canonicalPreimage{}, fmt.Errorf("unknown contract id preimage type %d", preimage.Type)
	}
}

func encodeCanonicalExecutable(executable xdr.ContractExecutable) (canonicalExecutable, error) {
	switch executable.Type {
	case xdr.ContractExecutableTypeContractExecutableWasm:
		if executable.WasmHash == nil {
			return canonicalExecutable{}, fmt.Errorf("wasm arm has no hash")
		}
		hash := hex.EncodeToString(executable.WasmHash[:])
		return canonicalExecutable{Type: "wasm", WasmHash: &hash}, nil
	case xdr.ContractExecutableTypeContractExecutableStellarAsset:
		return canonicalExecutable{Type: "stellar_asset"}, nil
	case xdr.ContractExecutableTypeContractExecutableExternalRef:
		if executable.ExternalRef == nil {
			return canonicalExecutable{}, fmt.Errorf("external_ref arm has no reference")
		}
		owner, err := encodeCanonicalAddress(executable.ExternalRef.ExecutableOwner)
		if err != nil {
			return canonicalExecutable{}, err
		}
		tag := encodeCanonicalText(string(executable.ExternalRef.Tag))
		return canonicalExecutable{Type: "external_ref", Owner: &owner, Tag: &tag}, nil
	default:
		return canonicalExecutable{}, fmt.Errorf("unknown contract executable type %d", executable.Type)
	}
}

func encodeCanonicalAddress(address xdr.ScAddress) (canonicalAddress, error) {
	if address.Type == xdr.ScAddressTypeScAddressTypeAccount && address.AccountId == nil {
		return canonicalAddress{}, fmt.Errorf("account address arm has no account id")
	}
	if address.Type == xdr.ScAddressTypeScAddressTypeContract && address.ContractId == nil {
		return canonicalAddress{}, fmt.Errorf("contract address arm has no contract id")
	}
	if rendered, err := FormatAddress(address); err == nil {
		switch address.Type {
		case xdr.ScAddressTypeScAddressTypeAccount:
			return canonicalAddress{Type: "account", Account: rendered}, nil
		case xdr.ScAddressTypeScAddressTypeContract:
			return canonicalAddress{Type: "contract", Contract: rendered}, nil
		}
	}
	encoded, err := safeMarshalBase64(address)
	if err != nil {
		return canonicalAddress{}, fmt.Errorf("address: %w", err)
	}
	return canonicalAddress{Type: "xdr", XDR: encoded}, nil
}

func encodeCanonicalScVals(values []xdr.ScVal, depth int) ([]canonicalScVal, error) {
	out := make([]canonicalScVal, 0, len(values))
	for i, value := range values {
		encoded, err := encodeCanonicalScVal(value, depth)
		if err != nil {
			return nil, fmt.Errorf("value %d: %w", i, err)
		}
		out = append(out, encoded)
	}
	return out, nil
}

func encodeCanonicalScVal(value xdr.ScVal, depth int) (canonicalScVal, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return canonicalScVal{}, err
	}
	out := canonicalScVal{Type: scValTypeName(value.Type)}
	switch value.Type {
	case xdr.ScValTypeScvBool:
		if value.B == nil {
			return canonicalScVal{}, fmt.Errorf("bool arm is empty")
		}
		out.Bool = value.B
	case xdr.ScValTypeScvVoid, xdr.ScValTypeScvLedgerKeyContractInstance:
	case xdr.ScValTypeScvU32:
		if value.U32 == nil {
			return canonicalScVal{}, fmt.Errorf("u32 arm is empty")
		}
		v := uint32(*value.U32)
		out.U32 = &v
	case xdr.ScValTypeScvI32:
		if value.I32 == nil {
			return canonicalScVal{}, fmt.Errorf("i32 arm is empty")
		}
		v := int32(*value.I32)
		out.I32 = &v
	case xdr.ScValTypeScvU64:
		if value.U64 == nil {
			return canonicalScVal{}, fmt.Errorf("u64 arm is empty")
		}
		v := strconv.FormatUint(uint64(*value.U64), 10)
		out.U64 = &v
	case xdr.ScValTypeScvI64:
		if value.I64 == nil {
			return canonicalScVal{}, fmt.Errorf("i64 arm is empty")
		}
		v := strconv.FormatInt(int64(*value.I64), 10)
		out.I64 = &v
	case xdr.ScValTypeScvTimepoint:
		if value.Timepoint == nil {
			return canonicalScVal{}, fmt.Errorf("timepoint arm is empty")
		}
		v := strconv.FormatUint(uint64(*value.Timepoint), 10)
		out.Timepoint = &v
	case xdr.ScValTypeScvDuration:
		if value.Duration == nil {
			return canonicalScVal{}, fmt.Errorf("duration arm is empty")
		}
		v := strconv.FormatUint(uint64(*value.Duration), 10)
		out.Duration = &v
	case xdr.ScValTypeScvU128:
		if value.U128 == nil {
			return canonicalScVal{}, fmt.Errorf("u128 arm is empty")
		}
		out.U128 = &canonicalParts128{
			Hi: strconv.FormatUint(uint64(value.U128.Hi), 10),
			Lo: strconv.FormatUint(uint64(value.U128.Lo), 10),
		}
	case xdr.ScValTypeScvI128:
		if value.I128 == nil {
			return canonicalScVal{}, fmt.Errorf("i128 arm is empty")
		}
		out.I128 = &canonicalParts128{
			Hi: strconv.FormatInt(int64(value.I128.Hi), 10),
			Lo: strconv.FormatUint(uint64(value.I128.Lo), 10),
		}
	case xdr.ScValTypeScvU256:
		if value.U256 == nil {
			return canonicalScVal{}, fmt.Errorf("u256 arm is empty")
		}
		out.U256 = &canonicalParts256{
			HiHi: strconv.FormatUint(uint64(value.U256.HiHi), 10),
			HiLo: strconv.FormatUint(uint64(value.U256.HiLo), 10),
			LoHi: strconv.FormatUint(uint64(value.U256.LoHi), 10),
			LoLo: strconv.FormatUint(uint64(value.U256.LoLo), 10),
		}
	case xdr.ScValTypeScvI256:
		if value.I256 == nil {
			return canonicalScVal{}, fmt.Errorf("i256 arm is empty")
		}
		out.I256 = &canonicalParts256{
			HiHi: strconv.FormatInt(int64(value.I256.HiHi), 10),
			HiLo: strconv.FormatUint(uint64(value.I256.HiLo), 10),
			LoHi: strconv.FormatUint(uint64(value.I256.LoHi), 10),
			LoLo: strconv.FormatUint(uint64(value.I256.LoLo), 10),
		}
	case xdr.ScValTypeScvBytes:
		if value.Bytes == nil {
			return canonicalScVal{}, fmt.Errorf("bytes arm is empty")
		}
		v := base64.StdEncoding.EncodeToString([]byte(*value.Bytes))
		out.Bytes = &v
	case xdr.ScValTypeScvString:
		if value.Str == nil {
			return canonicalScVal{}, fmt.Errorf("string arm is empty")
		}
		v := encodeCanonicalText(string(*value.Str))
		out.String = &v
	case xdr.ScValTypeScvSymbol:
		if value.Sym == nil {
			return canonicalScVal{}, fmt.Errorf("symbol arm is empty")
		}
		v := encodeCanonicalText(string(*value.Sym))
		out.Symbol = &v
	case xdr.ScValTypeScvVec:
		if value.Vec == nil || *value.Vec == nil {
			out.Nil = true
		} else {
			items := make([]canonicalScVal, 0, len(**value.Vec))
			for i, item := range **value.Vec {
				encoded, err := encodeCanonicalScVal(item, depth+1)
				if err != nil {
					return canonicalScVal{}, fmt.Errorf("vec item %d: %w", i, err)
				}
				items = append(items, encoded)
			}
			out.Vec = &items
		}
	case xdr.ScValTypeScvMap:
		if value.Map == nil || *value.Map == nil {
			out.Nil = true
		} else {
			entries, err := encodeCanonicalMap(**value.Map, depth+1)
			if err != nil {
				return canonicalScVal{}, err
			}
			out.Map = &entries
		}
	case xdr.ScValTypeScvAddress:
		if value.Address == nil {
			return canonicalScVal{}, fmt.Errorf("address arm is empty")
		}
		address, err := encodeCanonicalAddress(*value.Address)
		if err != nil {
			return canonicalScVal{}, err
		}
		out.Address = &address
	case xdr.ScValTypeScvContractInstance:
		if value.Instance == nil {
			return canonicalScVal{}, fmt.Errorf("contract_instance arm is empty")
		}
		instance, err := encodeCanonicalInstance(*value.Instance, depth+1)
		if err != nil {
			return canonicalScVal{}, err
		}
		out.Instance = &instance
	case xdr.ScValTypeScvExecutableTag:
		if value.ExecutableTag == nil {
			return canonicalScVal{}, fmt.Errorf("executable_tag arm is empty")
		}
		tag := encodeCanonicalText(string(*value.ExecutableTag))
		out.ExecutableTag = &tag
	case xdr.ScValTypeScvError:
		if value.Error == nil {
			return canonicalScVal{}, fmt.Errorf("error arm is empty")
		}
		encoded, err := safeMarshalBase64(value)
		if err != nil {
			return canonicalScVal{}, fmt.Errorf("error value: %w", err)
		}
		out.XDR = encoded
	case xdr.ScValTypeScvLedgerKeyNonce:
		if value.NonceKey == nil {
			return canonicalScVal{}, fmt.Errorf("ledger_key_nonce arm is empty")
		}
		encoded, err := safeMarshalBase64(value)
		if err != nil {
			return canonicalScVal{}, fmt.Errorf("ledger key nonce: %w", err)
		}
		out.XDR = encoded
	default:
		return canonicalScVal{}, fmt.Errorf("unknown ScVal type %d", value.Type)
	}
	return out, nil
}

func encodeCanonicalMap(entries []xdr.ScMapEntry, depth int) ([]canonicalMapEntry, error) {
	out := make([]canonicalMapEntry, 0, len(entries))
	for i, entry := range entries {
		key, err := encodeCanonicalScVal(entry.Key, depth)
		if err != nil {
			return nil, fmt.Errorf("map key %d: %w", i, err)
		}
		val, err := encodeCanonicalScVal(entry.Val, depth)
		if err != nil {
			return nil, fmt.Errorf("map value %d: %w", i, err)
		}
		out = append(out, canonicalMapEntry{Key: key, Val: val})
	}
	return out, nil
}

func encodeCanonicalInstance(instance xdr.ScContractInstance, depth int) (canonicalInstance, error) {
	executable, err := encodeCanonicalExecutable(instance.Executable)
	if err != nil {
		return canonicalInstance{}, err
	}
	out := canonicalInstance{Executable: executable}
	if instance.Storage != nil {
		storage, err := encodeCanonicalMap(*instance.Storage, depth)
		if err != nil {
			return canonicalInstance{}, err
		}
		out.Storage = &storage
	}
	return out, nil
}

func encodeCanonicalText(value string) canonicalText {
	if utf8.ValidString(value) {
		return canonicalText{UTF8: &value}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(value))
	return canonicalText{Base64: &encoded}
}

func scValTypeName(value xdr.ScValType) string {
	switch value {
	case xdr.ScValTypeScvBool:
		return "bool"
	case xdr.ScValTypeScvVoid:
		return "void"
	case xdr.ScValTypeScvError:
		return "error"
	case xdr.ScValTypeScvU32:
		return "u32"
	case xdr.ScValTypeScvI32:
		return "i32"
	case xdr.ScValTypeScvU64:
		return "u64"
	case xdr.ScValTypeScvI64:
		return "i64"
	case xdr.ScValTypeScvTimepoint:
		return "timepoint"
	case xdr.ScValTypeScvDuration:
		return "duration"
	case xdr.ScValTypeScvU128:
		return "u128"
	case xdr.ScValTypeScvI128:
		return "i128"
	case xdr.ScValTypeScvU256:
		return "u256"
	case xdr.ScValTypeScvI256:
		return "i256"
	case xdr.ScValTypeScvBytes:
		return "bytes"
	case xdr.ScValTypeScvString:
		return "string"
	case xdr.ScValTypeScvSymbol:
		return "symbol"
	case xdr.ScValTypeScvVec:
		return "vec"
	case xdr.ScValTypeScvMap:
		return "map"
	case xdr.ScValTypeScvAddress:
		return "address"
	case xdr.ScValTypeScvContractInstance:
		return "contract_instance"
	case xdr.ScValTypeScvLedgerKeyContractInstance:
		return "ledger_key_contract_instance"
	case xdr.ScValTypeScvLedgerKeyNonce:
		return "ledger_key_nonce"
	case xdr.ScValTypeScvExecutableTag:
		return "executable_tag"
	default:
		return ""
	}
}

func safeMarshalXDR(value interface{}) ([]byte, error) {
	var encoded []byte
	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("XDR encoding panicked: %v", recovered)
			}
		}()
		switch typed := value.(type) {
		case xdr.SorobanAuthorizationEntry:
			encoded, err = typed.MarshalBinary()
		default:
			err = fmt.Errorf("unsupported XDR value %T", value)
		}
	}()
	return encoded, err
}

func safeMarshalBase64(value interface{}) (string, error) {
	var encoded string
	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("XDR encoding panicked: %v", recovered)
			}
		}()
		switch typed := value.(type) {
		case xdr.ScAddress:
			encoded, err = xdr.MarshalBase64(typed)
		case xdr.Asset:
			encoded, err = xdr.MarshalBase64(typed)
		case xdr.ScVal:
			encoded, err = xdr.MarshalBase64(typed)
		default:
			err = fmt.Errorf("unsupported XDR value %T", value)
		}
	}()
	return encoded, err
}

func decodeCanonicalCredentials(credentials canonicalCredential, depth int) (xdr.SorobanCredentials, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return xdr.SorobanCredentials{}, err
	}

	switch credentials.Type {
	case CredentialTypeSourceAccount:
		if err := requireCredentialFields(credentials); err != nil {
			return xdr.SorobanCredentials{}, err
		}
		return xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		}, nil

	case CredentialTypeAddress, CredentialTypeAddressV2:
		if credentials.Delegates != nil {
			return xdr.SorobanCredentials{}, fmt.Errorf("%s credentials carry a delegates array", credentials.Type)
		}
		arm, err := decodeCanonicalAddressCredentials(credentials, depth)
		if err != nil {
			return xdr.SorobanCredentials{}, err
		}
		credentialsType := xdr.SorobanCredentialsTypeSorobanCredentialsAddress
		if credentials.Type == CredentialTypeAddressV2 {
			credentialsType = xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2
		}
		if credentials.Type == CredentialTypeAddress {
			return xdr.SorobanCredentials{Type: credentialsType, Address: &arm}, nil
		}
		return xdr.SorobanCredentials{Type: credentialsType, AddressV2: &arm}, nil

	case CredentialTypeAddressWithDelegates:
		if credentials.Delegates == nil {
			return xdr.SorobanCredentials{}, fmt.Errorf("address_with_delegates credentials have no delegates array")
		}
		arm, err := decodeCanonicalAddressCredentials(credentials, depth)
		if err != nil {
			return xdr.SorobanCredentials{}, err
		}
		nodes, err := decodeCanonicalDelegates(*credentials.Delegates, depth+1)
		if err != nil {
			return xdr.SorobanCredentials{}, err
		}
		return xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: arm,
				Delegates:          nodes,
			},
		}, nil

	default:
		return xdr.SorobanCredentials{}, fmt.Errorf("unknown credentials type %q", credentials.Type)
	}
}

func requireCredentialFields(credentials canonicalCredential) error {
	if credentials.Address != nil || credentials.Nonce != nil ||
		credentials.SignatureExpirationLedger != nil || credentials.Signature != nil ||
		credentials.Delegates != nil {
		return fmt.Errorf("source_account credentials carry address-arm fields")
	}
	return nil
}

func decodeCanonicalAddressCredentials(credentials canonicalCredential, depth int) (xdr.SorobanAddressCredentials, error) {
	if credentials.Address == nil {
		return xdr.SorobanAddressCredentials{}, fmt.Errorf("%s credentials have no address", credentials.Type)
	}
	if credentials.Nonce == nil {
		return xdr.SorobanAddressCredentials{}, fmt.Errorf("%s credentials have no nonce", credentials.Type)
	}
	if credentials.SignatureExpirationLedger == nil {
		return xdr.SorobanAddressCredentials{}, fmt.Errorf("%s credentials have no signature_expiration_ledger", credentials.Type)
	}
	if credentials.Signature == nil {
		return xdr.SorobanAddressCredentials{}, fmt.Errorf("%s credentials have no signature", credentials.Type)
	}
	address, err := decodeCanonicalAddress(*credentials.Address)
	if err != nil {
		return xdr.SorobanAddressCredentials{}, err
	}
	nonce, err := decodeCanonicalInt64(*credentials.Nonce, "nonce")
	if err != nil {
		return xdr.SorobanAddressCredentials{}, err
	}
	signature, err := decodeCanonicalScVal(*credentials.Signature, depth+1)
	if err != nil {
		return xdr.SorobanAddressCredentials{}, err
	}
	return xdr.SorobanAddressCredentials{
		Address:                   address,
		Nonce:                     xdr.Int64(nonce),
		SignatureExpirationLedger: xdr.Uint32(*credentials.SignatureExpirationLedger),
		Signature:                 signature,
	}, nil
}

func decodeCanonicalDelegates(delegates []canonicalDelegate, depth int) ([]xdr.SorobanDelegateSignature, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return nil, err
	}
	out := make([]xdr.SorobanDelegateSignature, 0, len(delegates))
	for i, delegate := range delegates {
		address, err := decodeCanonicalAddress(delegate.Address)
		if err != nil {
			return nil, fmt.Errorf("delegate %d address: %w", i, err)
		}
		signature, err := decodeCanonicalScVal(delegate.Signature, depth+1)
		if err != nil {
			return nil, fmt.Errorf("delegate %d signature: %w", i, err)
		}
		nested, err := decodeCanonicalDelegates(delegate.Nested, depth+1)
		if err != nil {
			return nil, fmt.Errorf("delegate %d: %w", i, err)
		}
		out = append(out, xdr.SorobanDelegateSignature{
			Address:         address,
			Signature:       signature,
			NestedDelegates: nested,
		})
	}
	return out, nil
}

func decodeCanonicalInvocation(invocation canonicalInvocation, depth int) (xdr.SorobanAuthorizedInvocation, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return xdr.SorobanAuthorizedInvocation{}, err
	}
	function, err := decodeCanonicalFunction(invocation.Function, depth+1)
	if err != nil {
		return xdr.SorobanAuthorizedInvocation{}, err
	}
	subs := make([]xdr.SorobanAuthorizedInvocation, 0, len(invocation.SubInvocations))
	for i, sub := range invocation.SubInvocations {
		decoded, err := decodeCanonicalInvocation(sub, depth+1)
		if err != nil {
			return xdr.SorobanAuthorizedInvocation{}, fmt.Errorf("sub-invocation %d: %w", i, err)
		}
		subs = append(subs, decoded)
	}
	return xdr.SorobanAuthorizedInvocation{Function: function, SubInvocations: subs}, nil
}

func decodeCanonicalFunction(function canonicalFunction, depth int) (xdr.SorobanAuthorizedFunction, error) {
	switch function.Type {
	case "contract_fn":
		if function.ContractIDPreimage != nil || function.Executable != nil || function.ConstructorArgs != nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("contract_fn function carries create-contract fields")
		}
		if function.ContractAddress == nil || function.FunctionName == nil || function.Args == nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("contract_fn function is missing contract_address, function_name, or args")
		}
		address, err := decodeCanonicalAddress(*function.ContractAddress)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		name, err := decodeCanonicalText(*function.FunctionName)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("function_name: %w", err)
		}
		args, err := decodeCanonicalScVals(*function.Args, depth+1)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		return xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: address,
				FunctionName:    xdr.ScSymbol(name),
				Args:            args,
			},
		}, nil

	case "create_contract_host_fn":
		if function.ContractAddress != nil || function.FunctionName != nil || function.Args != nil || function.ConstructorArgs != nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("create_contract_host_fn function carries contract-call fields")
		}
		if function.ContractIDPreimage == nil || function.Executable == nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("create_contract_host_fn function is missing contract_id_preimage or executable")
		}
		preimage, err := decodeCanonicalPreimage(*function.ContractIDPreimage)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		executable, err := decodeCanonicalExecutable(*function.Executable)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		return xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
			CreateContractHostFn: &xdr.CreateContractArgs{
				ContractIdPreimage: preimage,
				Executable:         executable,
			},
		}, nil

	case "create_contract_v2_host_fn":
		if function.ContractAddress != nil || function.FunctionName != nil || function.Args != nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("create_contract_v2_host_fn function carries contract-call fields")
		}
		if function.ContractIDPreimage == nil || function.Executable == nil || function.ConstructorArgs == nil {
			return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("create_contract_v2_host_fn function is missing contract_id_preimage, executable, or constructor_args")
		}
		preimage, err := decodeCanonicalPreimage(*function.ContractIDPreimage)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		executable, err := decodeCanonicalExecutable(*function.Executable)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		args, err := decodeCanonicalScVals(*function.ConstructorArgs, depth+1)
		if err != nil {
			return xdr.SorobanAuthorizedFunction{}, err
		}
		return xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn,
			CreateContractV2HostFn: &xdr.CreateContractArgsV2{
				ContractIdPreimage: preimage,
				Executable:         executable,
				ConstructorArgs:    args,
			},
		}, nil

	default:
		return xdr.SorobanAuthorizedFunction{}, fmt.Errorf("unknown function type %q", function.Type)
	}
}

func decodeCanonicalPreimage(preimage canonicalPreimage) (xdr.ContractIdPreimage, error) {
	switch preimage.Type {
	case "from_address":
		if preimage.Address == nil || preimage.Salt == nil || preimage.XDR != "" {
			return xdr.ContractIdPreimage{}, fmt.Errorf("from_address preimage is missing address or salt")
		}
		address, err := decodeCanonicalAddress(*preimage.Address)
		if err != nil {
			return xdr.ContractIdPreimage{}, err
		}
		salt, err := decodeCanonicalHex(*preimage.Salt, 32, "salt")
		if err != nil {
			return xdr.ContractIdPreimage{}, err
		}
		var salt256 xdr.Uint256
		copy(salt256[:], salt)
		return xdr.ContractIdPreimage{
			Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
			FromAddress: &xdr.ContractIdPreimageFromAddress{
				Address: address,
				Salt:    salt256,
			},
		}, nil

	case "from_asset":
		if preimage.Address != nil || preimage.Salt != nil || preimage.XDR == "" {
			return xdr.ContractIdPreimage{}, fmt.Errorf("from_asset preimage carries from_address fields or no xdr")
		}
		var asset xdr.Asset
		if err := decodeCanonicalXDR(preimage.XDR, &asset); err != nil {
			return xdr.ContractIdPreimage{}, fmt.Errorf("from_asset: %w", err)
		}
		return xdr.ContractIdPreimage{
			Type:      xdr.ContractIdPreimageTypeContractIdPreimageFromAsset,
			FromAsset: &asset,
		}, nil

	default:
		return xdr.ContractIdPreimage{}, fmt.Errorf("unknown contract_id_preimage type %q", preimage.Type)
	}
}

func decodeCanonicalExecutable(executable canonicalExecutable) (xdr.ContractExecutable, error) {
	switch executable.Type {
	case "wasm":
		if executable.WasmHash == nil || executable.Owner != nil || executable.Tag != nil {
			return xdr.ContractExecutable{}, fmt.Errorf("wasm executable is missing wasm_hash or carries external_ref fields")
		}
		hash, err := decodeCanonicalHex(*executable.WasmHash, 32, "wasm_hash")
		if err != nil {
			return xdr.ContractExecutable{}, err
		}
		var wasm xdr.Hash
		copy(wasm[:], hash)
		return xdr.ContractExecutable{
			Type:     xdr.ContractExecutableTypeContractExecutableWasm,
			WasmHash: &wasm,
		}, nil

	case "stellar_asset":
		if executable.WasmHash != nil || executable.Owner != nil || executable.Tag != nil {
			return xdr.ContractExecutable{}, fmt.Errorf("stellar_asset executable carries wasm or external_ref fields")
		}
		return xdr.ContractExecutable{
			Type: xdr.ContractExecutableTypeContractExecutableStellarAsset,
		}, nil

	case "external_ref":
		if executable.WasmHash != nil || executable.Owner == nil || executable.Tag == nil {
			return xdr.ContractExecutable{}, fmt.Errorf("external_ref executable is missing owner or tag")
		}
		owner, err := decodeCanonicalAddress(*executable.Owner)
		if err != nil {
			return xdr.ContractExecutable{}, err
		}
		tag, err := decodeCanonicalText(*executable.Tag)
		if err != nil {
			return xdr.ContractExecutable{}, fmt.Errorf("external_ref tag: %w", err)
		}
		return xdr.ContractExecutable{
			Type: xdr.ContractExecutableTypeContractExecutableExternalRef,
			ExternalRef: &xdr.ContractExecutableExternalRef{
				ExecutableOwner: owner,
				Tag:             xdr.ScString(tag),
			},
		}, nil

	default:
		return xdr.ContractExecutable{}, fmt.Errorf("unknown executable type %q", executable.Type)
	}
}

func decodeCanonicalAddress(address canonicalAddress) (xdr.ScAddress, error) {
	switch address.Type {
	case "account":
		if address.Account == "" || address.Contract != "" || address.XDR != "" {
			return xdr.ScAddress{}, fmt.Errorf("account address is missing account or carries another arm")
		}
		parsed, err := ParseAddress(address.Account)
		if err != nil {
			return xdr.ScAddress{}, err
		}
		if parsed.Type != xdr.ScAddressTypeScAddressTypeAccount {
			return xdr.ScAddress{}, fmt.Errorf("%q is not an account address", address.Account)
		}
		return parsed, nil

	case "contract":
		if address.Contract == "" || address.Account != "" || address.XDR != "" {
			return xdr.ScAddress{}, fmt.Errorf("contract address is missing contract or carries another arm")
		}
		parsed, err := ParseAddress(address.Contract)
		if err != nil {
			return xdr.ScAddress{}, err
		}
		if parsed.Type != xdr.ScAddressTypeScAddressTypeContract {
			return xdr.ScAddress{}, fmt.Errorf("%q is not a contract address", address.Contract)
		}
		return parsed, nil

	case "xdr":
		if address.XDR == "" || address.Account != "" || address.Contract != "" {
			return xdr.ScAddress{}, fmt.Errorf("xdr address is missing xdr or carries another arm")
		}
		var parsed xdr.ScAddress
		if err := decodeCanonicalXDR(address.XDR, &parsed); err != nil {
			return xdr.ScAddress{}, fmt.Errorf("address xdr: %w", err)
		}
		return parsed, nil

	default:
		return xdr.ScAddress{}, fmt.Errorf("unknown address type %q", address.Type)
	}
}

func decodeCanonicalText(text canonicalText) (string, error) {
	if (text.UTF8 == nil) == (text.Base64 == nil) {
		return "", fmt.Errorf("text must carry exactly one of utf8 or base64")
	}
	if text.UTF8 != nil {
		return *text.UTF8, nil
	}
	decoded, err := decodeCanonicalBase64(*text.Base64)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decodeCanonicalScVals(values []canonicalScVal, depth int) ([]xdr.ScVal, error) {
	out := make([]xdr.ScVal, 0, len(values))
	for i, value := range values {
		decoded, err := decodeCanonicalScVal(value, depth)
		if err != nil {
			return nil, fmt.Errorf("value %d: %w", i, err)
		}
		out = append(out, decoded)
	}
	return out, nil
}

func decodeCanonicalScVal(value canonicalScVal, depth int) (xdr.ScVal, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return xdr.ScVal{}, err
	}

	switch value.Type {
	case "bool":
		if err := requireScValFields(value, "bool"); err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvBool, B: value.Bool}, nil

	case "void":
		if err := requireScValFields(value); err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil

	case "u32":
		if err := requireScValFields(value, "u32"); err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.Uint32(*value.U32)
		return xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &converted}, nil

	case "i32":
		if err := requireScValFields(value, "i32"); err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.Int32(*value.I32)
		return xdr.ScVal{Type: xdr.ScValTypeScvI32, I32: &converted}, nil

	case "u64":
		if err := requireScValFields(value, "u64"); err != nil {
			return xdr.ScVal{}, err
		}
		parsed, err := decodeCanonicalUint64(*value.U64, "u64")
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.Uint64(parsed)
		return xdr.ScVal{Type: xdr.ScValTypeScvU64, U64: &converted}, nil

	case "i64":
		if err := requireScValFields(value, "i64"); err != nil {
			return xdr.ScVal{}, err
		}
		parsed, err := decodeCanonicalInt64(*value.I64, "i64")
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.Int64(parsed)
		return xdr.ScVal{Type: xdr.ScValTypeScvI64, I64: &converted}, nil

	case "timepoint":
		if err := requireScValFields(value, "timepoint"); err != nil {
			return xdr.ScVal{}, err
		}
		parsed, err := decodeCanonicalUint64(*value.Timepoint, "timepoint")
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.TimePoint(parsed)
		return xdr.ScVal{Type: xdr.ScValTypeScvTimepoint, Timepoint: &converted}, nil

	case "duration":
		if err := requireScValFields(value, "duration"); err != nil {
			return xdr.ScVal{}, err
		}
		parsed, err := decodeCanonicalUint64(*value.Duration, "duration")
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.Duration(parsed)
		return xdr.ScVal{Type: xdr.ScValTypeScvDuration, Duration: &converted}, nil

	case "u128":
		if err := requireScValFields(value, "u128"); err != nil {
			return xdr.ScVal{}, err
		}
		parts, err := decodeCanonicalU128Parts(value.U128)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvU128, U128: &parts}, nil

	case "i128":
		if err := requireScValFields(value, "i128"); err != nil {
			return xdr.ScVal{}, err
		}
		parts, err := decodeCanonicalI128Parts(value.I128)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &parts}, nil

	case "u256":
		if err := requireScValFields(value, "u256"); err != nil {
			return xdr.ScVal{}, err
		}
		parts, err := decodeCanonicalU256Parts(value.U256)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvU256, U256: &parts}, nil

	case "i256":
		if err := requireScValFields(value, "i256"); err != nil {
			return xdr.ScVal{}, err
		}
		parts, err := decodeCanonicalI256Parts(value.I256)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvI256, I256: &parts}, nil

	case "bytes":
		if err := requireScValFields(value, "bytes"); err != nil {
			return xdr.ScVal{}, err
		}
		decoded, err := decodeCanonicalBase64(*value.Bytes)
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.ScBytes(decoded)
		return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &converted}, nil

	case "string":
		if err := requireScValFields(value, "string"); err != nil {
			return xdr.ScVal{}, err
		}
		decoded, err := decodeCanonicalText(*value.String)
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.ScString(decoded)
		return xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &converted}, nil

	case "symbol":
		if err := requireScValFields(value, "symbol"); err != nil {
			return xdr.ScVal{}, err
		}
		decoded, err := decodeCanonicalText(*value.Symbol)
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.ScSymbol(decoded)
		return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &converted}, nil

	case "vec":
		if value.Nil {
			if err := requireScValFields(value, "nil"); err != nil {
				return xdr.ScVal{}, err
			}
			var vector *xdr.ScVec
			return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &vector}, nil
		}
		if err := requireScValFields(value, "vec"); err != nil {
			return xdr.ScVal{}, err
		}
		items, err := decodeCanonicalScVals(*value.Vec, depth+1)
		if err != nil {
			return xdr.ScVal{}, err
		}
		vector := xdr.ScVec(items)
		vectorPointer := &vector
		return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &vectorPointer}, nil

	case "map":
		if value.Nil {
			if err := requireScValFields(value, "nil"); err != nil {
				return xdr.ScVal{}, err
			}
			var valueMap *xdr.ScMap
			return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &valueMap}, nil
		}
		if err := requireScValFields(value, "map"); err != nil {
			return xdr.ScVal{}, err
		}
		entries, err := decodeCanonicalMap(*value.Map, depth+1)
		if err != nil {
			return xdr.ScVal{}, err
		}
		valueMap := xdr.ScMap(entries)
		mapPointer := &valueMap
		return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &mapPointer}, nil

	case "address":
		if err := requireScValFields(value, "address"); err != nil {
			return xdr.ScVal{}, err
		}
		address, err := decodeCanonicalAddress(*value.Address)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &address}, nil

	case "contract_instance":
		if err := requireScValFields(value, "contract_instance"); err != nil {
			return xdr.ScVal{}, err
		}
		instance, err := decodeCanonicalInstance(*value.Instance, depth+1)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvContractInstance, Instance: &instance}, nil

	case "ledger_key_contract_instance":
		if err := requireScValFields(value); err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvLedgerKeyContractInstance}, nil

	case "executable_tag":
		if err := requireScValFields(value, "executable_tag"); err != nil {
			return xdr.ScVal{}, err
		}
		decoded, err := decodeCanonicalText(*value.ExecutableTag)
		if err != nil {
			return xdr.ScVal{}, err
		}
		converted := xdr.ScString(decoded)
		return xdr.ScVal{Type: xdr.ScValTypeScvExecutableTag, ExecutableTag: &converted}, nil

	case "error":
		if err := requireScValFields(value, "xdr"); err != nil {
			return xdr.ScVal{}, err
		}
		return decodeCanonicalScValXDR(value.XDR, xdr.ScValTypeScvError)

	case "ledger_key_nonce":
		if err := requireScValFields(value, "xdr"); err != nil {
			return xdr.ScVal{}, err
		}
		return decodeCanonicalScValXDR(value.XDR, xdr.ScValTypeScvLedgerKeyNonce)

	default:
		return xdr.ScVal{}, fmt.Errorf("unknown ScVal type %q", value.Type)
	}
}

func decodeCanonicalMap(entries []canonicalMapEntry, depth int) ([]xdr.ScMapEntry, error) {
	out := make([]xdr.ScMapEntry, 0, len(entries))
	for i, entry := range entries {
		key, err := decodeCanonicalScVal(entry.Key, depth)
		if err != nil {
			return nil, fmt.Errorf("map key %d: %w", i, err)
		}
		val, err := decodeCanonicalScVal(entry.Val, depth)
		if err != nil {
			return nil, fmt.Errorf("map value %d: %w", i, err)
		}
		out = append(out, xdr.ScMapEntry{Key: key, Val: val})
	}
	return out, nil
}

func decodeCanonicalInstance(instance canonicalInstance, depth int) (xdr.ScContractInstance, error) {
	executable, err := decodeCanonicalExecutable(instance.Executable)
	if err != nil {
		return xdr.ScContractInstance{}, err
	}
	out := xdr.ScContractInstance{Executable: executable}
	if instance.Storage != nil {
		entries, err := decodeCanonicalMap(*instance.Storage, depth)
		if err != nil {
			return xdr.ScContractInstance{}, err
		}
		storage := xdr.ScMap(entries)
		out.Storage = &storage
	}
	return out, nil
}

func requireScValFields(value canonicalScVal, want ...string) error {
	present := make(map[string]bool)
	if value.Bool != nil {
		present["bool"] = true
	}
	if value.U32 != nil {
		present["u32"] = true
	}
	if value.I32 != nil {
		present["i32"] = true
	}
	if value.U64 != nil {
		present["u64"] = true
	}
	if value.I64 != nil {
		present["i64"] = true
	}
	if value.Timepoint != nil {
		present["timepoint"] = true
	}
	if value.Duration != nil {
		present["duration"] = true
	}
	if value.U128 != nil {
		present["u128"] = true
	}
	if value.I128 != nil {
		present["i128"] = true
	}
	if value.U256 != nil {
		present["u256"] = true
	}
	if value.I256 != nil {
		present["i256"] = true
	}
	if value.Bytes != nil {
		present["bytes"] = true
	}
	if value.String != nil {
		present["string"] = true
	}
	if value.Symbol != nil {
		present["symbol"] = true
	}
	if value.Vec != nil {
		present["vec"] = true
	}
	if value.Map != nil {
		present["map"] = true
	}
	if value.Nil {
		present["nil"] = true
	}
	if value.Address != nil {
		present["address"] = true
	}
	if value.Instance != nil {
		present["contract_instance"] = true
	}
	if value.XDR != "" {
		present["xdr"] = true
	}
	if value.ExecutableTag != nil {
		present["executable_tag"] = true
	}
	if len(present) != len(want) {
		return fmt.Errorf("ScVal type %q carries %d value fields, want %d", value.Type, len(present), len(want))
	}
	for _, field := range want {
		if !present[field] {
			return fmt.Errorf("ScVal type %q has no %s field", value.Type, field)
		}
	}
	return nil
}

func decodeCanonicalU128Parts(parts *canonicalParts128) (xdr.UInt128Parts, error) {
	if parts == nil {
		return xdr.UInt128Parts{}, fmt.Errorf("u128 has no value")
	}
	hi, err := decodeCanonicalUint64(parts.Hi, "u128.hi")
	if err != nil {
		return xdr.UInt128Parts{}, err
	}
	lo, err := decodeCanonicalUint64(parts.Lo, "u128.lo")
	if err != nil {
		return xdr.UInt128Parts{}, err
	}
	return xdr.UInt128Parts{Hi: xdr.Uint64(hi), Lo: xdr.Uint64(lo)}, nil
}

func decodeCanonicalI128Parts(parts *canonicalParts128) (xdr.Int128Parts, error) {
	if parts == nil {
		return xdr.Int128Parts{}, fmt.Errorf("i128 has no value")
	}
	hi, err := decodeCanonicalInt64(parts.Hi, "i128.hi")
	if err != nil {
		return xdr.Int128Parts{}, err
	}
	lo, err := decodeCanonicalUint64(parts.Lo, "i128.lo")
	if err != nil {
		return xdr.Int128Parts{}, err
	}
	return xdr.Int128Parts{Hi: xdr.Int64(hi), Lo: xdr.Uint64(lo)}, nil
}

func decodeCanonicalU256Parts(parts *canonicalParts256) (xdr.UInt256Parts, error) {
	if parts == nil {
		return xdr.UInt256Parts{}, fmt.Errorf("u256 has no value")
	}
	hiHi, err := decodeCanonicalUint64(parts.HiHi, "u256.hi_hi")
	if err != nil {
		return xdr.UInt256Parts{}, err
	}
	hiLo, err := decodeCanonicalUint64(parts.HiLo, "u256.hi_lo")
	if err != nil {
		return xdr.UInt256Parts{}, err
	}
	loHi, err := decodeCanonicalUint64(parts.LoHi, "u256.lo_hi")
	if err != nil {
		return xdr.UInt256Parts{}, err
	}
	loLo, err := decodeCanonicalUint64(parts.LoLo, "u256.lo_lo")
	if err != nil {
		return xdr.UInt256Parts{}, err
	}
	return xdr.UInt256Parts{
		HiHi: xdr.Uint64(hiHi),
		HiLo: xdr.Uint64(hiLo),
		LoHi: xdr.Uint64(loHi),
		LoLo: xdr.Uint64(loLo),
	}, nil
}

func decodeCanonicalI256Parts(parts *canonicalParts256) (xdr.Int256Parts, error) {
	if parts == nil {
		return xdr.Int256Parts{}, fmt.Errorf("i256 has no value")
	}
	hiHi, err := decodeCanonicalInt64(parts.HiHi, "i256.hi_hi")
	if err != nil {
		return xdr.Int256Parts{}, err
	}
	hiLo, err := decodeCanonicalUint64(parts.HiLo, "i256.hi_lo")
	if err != nil {
		return xdr.Int256Parts{}, err
	}
	loHi, err := decodeCanonicalUint64(parts.LoHi, "i256.lo_hi")
	if err != nil {
		return xdr.Int256Parts{}, err
	}
	loLo, err := decodeCanonicalUint64(parts.LoLo, "i256.lo_lo")
	if err != nil {
		return xdr.Int256Parts{}, err
	}
	return xdr.Int256Parts{
		HiHi: xdr.Int64(hiHi),
		HiLo: xdr.Uint64(hiLo),
		LoHi: xdr.Uint64(loHi),
		LoLo: xdr.Uint64(loLo),
	}, nil
}

func decodeCanonicalScValXDR(encoded string, expected xdr.ScValType) (xdr.ScVal, error) {
	var value xdr.ScVal
	if err := decodeCanonicalXDR(encoded, &value); err != nil {
		return xdr.ScVal{}, err
	}
	if value.Type != expected {
		return xdr.ScVal{}, fmt.Errorf("xdr value has type %d, want %d", value.Type, expected)
	}
	return value, nil
}

func decodeCanonicalXDR(encoded string, destination interface{}) error {
	raw, err := decodeCanonicalBase64(encoded)
	if err != nil {
		return err
	}
	if err := xdr.SafeUnmarshalBase64WithOptions(encoded, destination, xdr.DecodeOptions{
		MaxDepth: MaxDecodeDepth,
	}); err != nil {
		return fmt.Errorf("decoding xdr: %w", err)
	}
	marshaled, err := marshalCanonicalXDRValue(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, marshaled) {
		return fmt.Errorf("xdr is not the canonical encoding of its value")
	}
	return nil
}

func marshalCanonicalXDRValue(value interface{}) ([]byte, error) {
	var encoded []byte
	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("XDR encoding panicked: %v", recovered)
			}
		}()
		switch typed := value.(type) {
		case *xdr.ScAddress:
			encoded, err = typed.MarshalBinary()
		case *xdr.Asset:
			encoded, err = typed.MarshalBinary()
		case *xdr.ScVal:
			encoded, err = typed.MarshalBinary()
		default:
			err = fmt.Errorf("unsupported XDR value %T", value)
		}
	}()
	return encoded, err
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("base64 value is empty")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("base64 is not canonical")
	}
	return decoded, nil
}

func decodeCanonicalHex(value string, length int, name string) ([]byte, error) {
	if len(value) != length*2 {
		return nil, fmt.Errorf("%s is %d hex characters, want %d", name, len(value), length*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if hex.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is not lowercase canonical hex", name)
	}
	return decoded, nil
}

func decodeCanonicalUint64(value string, name string) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is empty", name)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s %q is not a canonical uint64", name, value)
	}
	return parsed, nil
}

func decodeCanonicalInt64(value string, name string) (int64, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is empty", name)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != value {
		return 0, fmt.Errorf("%s %q is not a canonical int64", name, value)
	}
	return parsed, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != nil {
		if err.Error() == "EOF" {
			return nil
		}
		return err
	}
	return fmt.Errorf("trailing data after the JSON value")
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > MaxDecodeDepth*8 {
		return fmt.Errorf("JSON nesting exceeds the %d-level limit: %w", MaxDecodeDepth*8, ErrDecodeLimit)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = true
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter %q", delimiter)
		}
	case nil, bool, string, json.Number:
		return nil
	default:
		return fmt.Errorf("unexpected JSON token %T", token)
	}
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("trailing data after the JSON value")
	} else if err.Error() != "EOF" {
		return err
	}
	return nil
}
