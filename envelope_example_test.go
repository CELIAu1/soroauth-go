package soroauth_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// The envelope fixtures use committed golden-vector entries, so the auth
// vectors carried by the transaction are the exact bytes the reference SDK
// produced.
const (
	envelopeExampleSource          = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"
	envelopeExampleFeeSource       = "GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO"
	envelopeExampleContract        = "CA2GWZB4O7LIPISULUNERN4GCUNMVZP7VIHLLL3A6XDPHI7QD6VNCMEV"
	envelopeExampleV2Vector        = "testdata/vectors/v2_single_testnet.json"
	envelopeExampleDelegatesVector = "testdata/vectors/delegates_single_node.json"
)

func envelopeExampleEntry(path string) xdr.SorobanAuthorizationEntry {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var fixture struct {
		UnsignedEntryXDR string `json:"unsigned_entry_xdr"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(err)
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(fixture.UnsignedEntryXDR, &entry); err != nil {
		panic(err)
	}
	return entry
}

func envelopeExampleHostFunction() xdr.HostFunction {
	contract, err := soroauth.ParseAddress(envelopeExampleContract)
	if err != nil {
		panic(err)
	}
	return xdr.HostFunction{
		Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
		InvokeContract: &xdr.InvokeContractArgs{
			ContractAddress: contract,
			FunctionName:    xdr.ScSymbol("transfer"),
			Args:            []xdr.ScVal{},
		},
	}
}

func envelopeExampleInvoke(entries ...xdr.SorobanAuthorizationEntry) xdr.Operation {
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: envelopeExampleHostFunction(),
			Auth:         entries,
		},
	}}
}

func envelopeExamplePayment() xdr.Operation {
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypePayment,
		PaymentOp: &xdr.PaymentOp{
			Destination: xdr.MustMuxedAddress(envelopeExampleFeeSource),
			Asset:       xdr.Asset{Type: xdr.AssetTypeAssetTypeNative},
			Amount:      1,
		},
	}}
}

func envelopeExampleTransaction(operations ...xdr.Operation) xdr.TransactionEnvelope {
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: xdr.MustMuxedAddress(envelopeExampleSource),
			Fee:           100,
			SeqNum:        1,
			Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
			Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
			Operations:    operations,
			Ext:           xdr.TransactionExt{V: 0},
		}},
	}
}

func envelopeExampleFeeBump(inner xdr.TransactionEnvelope) xdr.TransactionEnvelope {
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
		FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
			FeeSource: xdr.MustMuxedAddress(envelopeExampleFeeSource),
			Fee:       200,
			InnerTx: xdr.FeeBumpTransactionInnerTx{
				Type: xdr.EnvelopeTypeEnvelopeTypeTx,
				V1:   inner.V1,
			},
			Ext: xdr.FeeBumpTransactionExt{V: 0},
		}},
	}
}

// ExampleEnvelopeEntries reads every authorization entry out of a transaction
// and reports where each one sits.
//
// The position is the part a caller cannot reconstruct later: signing changes
// the entry, and it has to be written back to the same operation and entry
// index or the submitted transaction authorizes something else. Here the first
// invoke operation carries two entries and the second carries one, so both
// indices are visible.
func ExampleEnvelopeEntries() {
	first := envelopeExampleEntry(envelopeExampleV2Vector)
	second := envelopeExampleEntry(envelopeExampleDelegatesVector)
	third := envelopeExampleEntry(envelopeExampleV2Vector)

	envelope := envelopeExampleTransaction(
		envelopeExampleInvoke(first, second),
		envelopeExampleInvoke(third),
	)

	entries, err := soroauth.EnvelopeEntries(envelope)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for _, located := range entries {
		info, err := soroauth.Inspect(located.Entry)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		fmt.Printf("operation=%d entry=%d arm=%s\n",
			located.OperationIndex, located.EntryIndex, info.CredentialType)
	}

	// Output:
	// operation=0 entry=0 arm=address_v2
	// operation=0 entry=1 arm=address_with_delegates
	// operation=1 entry=0 arm=address_v2
}

// ExampleInspectEnvelope_feeBump reads through a fee-bump envelope to the inner
// transaction.
//
// A fee-bump transaction has no operations of its own; the invoke operation
// lives in the inner transaction, and that is where the host looks for
// authorization entries. So the operation index below is an index into the
// inner transaction's operations, not into anything on the fee-bump envelope.
// The inner transaction has a payment first, which is why the invoke operation
// is at index 1 rather than 0.
func ExampleInspectEnvelope_feeBump() {
	entry := envelopeExampleEntry(envelopeExampleV2Vector)
	inner := envelopeExampleTransaction(
		envelopeExamplePayment(),
		envelopeExampleInvoke(entry),
	)

	infos, err := soroauth.InspectEnvelope(envelopeExampleFeeBump(inner))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for _, info := range infos {
		fmt.Printf("inner operation=%d entry=%d arm=%s function=%s\n",
			info.OperationIndex, info.EntryIndex, info.CredentialType, info.RootFunction)
	}

	// Output:
	// inner operation=1 entry=0 arm=address_v2 function=transfer
}
