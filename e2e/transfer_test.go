//go:build e2e

package e2e

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// nativeSAC returns the Stellar Asset Contract address for native XLM on this
// network.
func (h *harness) nativeSAC(t *testing.T) xdr.ScAddress {
	t.Helper()

	contractID, err := xdr.MustNewNativeAsset().ContractID(h.passphrase)
	if err != nil {
		t.Fatalf("deriving the native SAC contract id: %v", err)
	}
	id := xdr.ContractId(contractID)
	return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &id}
}

// scAddressOf parses any G… or C… address into an ScAddress.
func scAddressOf(t *testing.T, address string) xdr.ScAddress {
	t.Helper()

	if len(address) > 0 && address[0] == 'C' {
		raw, err := strkey.Decode(strkey.VersionByteContract, address)
		if err != nil {
			t.Fatalf("decoding contract address %s: %v", address, err)
		}
		var id xdr.ContractId
		copy(id[:], raw)
		return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &id}
	}

	accountID, err := xdr.AddressToAccountId(address)
	if err != nil {
		t.Fatalf("decoding account address %s: %v", address, err)
	}
	return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &accountID}
}

// i128 builds a non-negative i128 ScVal.
func i128(amount int64) xdr.ScVal {
	parts := xdr.Int128Parts{Hi: 0, Lo: xdr.Uint64(amount)}
	return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &parts}
}

// scAddressVal wraps an ScAddress as an ScVal argument.
func scAddressVal(address xdr.ScAddress) xdr.ScVal {
	return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &address}
}

// transferOp builds `transfer(from, to, amount)` against the native SAC, with
// the given operation source account. The operation source matters: it decides
// whose credentials the host uses for source-account auth, so a transfer from
// someone other than the payer is what forces a real address credential.
func (h *harness) transferOp(t *testing.T, from, to xdr.ScAddress, amount int64, opSource string) txnbuild.InvokeHostFunction {
	t.Helper()

	return txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: h.nativeSAC(t),
				FunctionName:    xdr.ScSymbol("transfer"),
				Args: xdr.ScVec{
					scAddressVal(from),
					scAddressVal(to),
					i128(amount),
				},
			},
		},
		SourceAccount: opSource,
	}
}
