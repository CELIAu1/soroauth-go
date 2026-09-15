package soroauth

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestUpgradeToV2ChangesOnlyTheArm(t *testing.T) {
	legacy := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)

	upgraded, err := UpgradeToV2(legacy)
	if err != nil {
		t.Fatalf("UpgradeToV2 returned an unexpected error: %v", err)
	}
	if upgraded.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
		t.Fatalf("arm is %v, want address v2", upgraded.Credentials.Type)
	}
	if upgraded.Credentials.Address != nil {
		t.Error("the legacy arm is still populated after the upgrade")
	}

	before, err := addressCredentials(legacy.Credentials)
	if err != nil {
		t.Fatalf("reading the legacy credentials: %v", err)
	}
	after, err := addressCredentials(upgraded.Credentials)
	if err != nil {
		t.Fatalf("reading the upgraded credentials: %v", err)
	}

	if after.Nonce != before.Nonce {
		t.Errorf("nonce changed from %d to %d", before.Nonce, after.Nonce)
	}
	if after.SignatureExpirationLedger != before.SignatureExpirationLedger {
		t.Errorf("expiration changed from %d to %d",
			before.SignatureExpirationLedger, after.SignatureExpirationLedger)
	}

	beforeAddress, err := addressBytes(before.Address)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	afterAddress, err := addressBytes(after.Address)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !bytes.Equal(beforeAddress, afterAddress) {
		t.Error("the upgraded entry names a different address")
	}

	beforeInvocation, err := legacy.RootInvocation.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	afterInvocation, err := upgraded.RootInvocation.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(beforeInvocation, afterInvocation) {
		t.Error("the upgraded entry carries a different invocation tree")
	}
}

// TestUpgradeToV2ChangesThePayload is the reason the upgrade exists and the
// reason a signed entry cannot be upgraded.
func TestUpgradeToV2ChangesThePayload(t *testing.T) {
	legacy := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)

	beforePreimage, err := Preimage(legacy, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the legacy preimage: %v", err)
	}
	beforePayload, err := Payload(beforePreimage)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	upgraded, err := UpgradeToV2(legacy)
	if err != nil {
		t.Fatalf("UpgradeToV2 returned an unexpected error: %v", err)
	}
	afterPreimage, err := Preimage(upgraded, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the upgraded preimage: %v", err)
	}
	afterPayload, err := Payload(afterPreimage)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	if beforePreimage.Type != xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization {
		t.Errorf("legacy envelope is %v, want the legacy variant", beforePreimage.Type)
	}
	if afterPreimage.Type != xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress {
		t.Errorf("upgraded envelope is %v, want the address-bound variant", afterPreimage.Type)
	}
	if beforePayload == afterPayload {
		t.Error("the upgrade left the payload unchanged; V2 must bind the address")
	}
}

func TestUpgradeToV2IsIdempotentForV2(t *testing.T) {
	v2 := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	want, err := v2.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	upgraded, err := UpgradeToV2(v2)
	if err != nil {
		t.Fatalf("UpgradeToV2 returned an unexpected error: %v", err)
	}
	got, err := upgraded.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("an already-V2 entry was changed\n want %x\n  got %x", want, got)
	}

	// It must be a copy, not the same memory, so callers can upgrade
	// unconditionally without aliasing their input.
	upgraded.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	after, err := v2.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(want, after) {
		t.Error("the returned entry shares memory with the input")
	}
}

// TestUpgradeToV2UpgradesSimulationPlaceholders makes sure the two unsigned
// placeholders simulation emits are not mistaken for signatures, which would
// make the function useless on exactly the entries it is meant for.
func TestUpgradeToV2UpgradesSimulationPlaceholders(t *testing.T) {
	placeholders := map[string]xdr.ScVal{
		"void":         {Type: xdr.ScValTypeScvVoid},
		"empty vector": scVec(),
	}

	for name, placeholder := range placeholders {
		t.Run(name, func(t *testing.T) {
			legacy := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
			legacy.Credentials.Address.Signature = placeholder

			upgraded, err := UpgradeToV2(legacy)
			if err != nil {
				t.Fatalf("UpgradeToV2 rejected a %s placeholder: %v", name, err)
			}
			if upgraded.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
				t.Errorf("arm is %v, want address v2", upgraded.Credentials.Type)
			}
		})
	}
}

func TestUpgradeToV2Rejects(t *testing.T) {
	signed := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
	signed.Credentials.Address.Signature = scVec(accountSignature(make([]byte, 32), make([]byte, 64)))

	emptyArm := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
	emptyArm.Credentials.Address = nil

	tests := []struct {
		name    string
		entry   xdr.SorobanAuthorizationEntry
		wantErr error
		wantMsg string
	}{
		{
			name:    "already signed",
			entry:   signed,
			wantErr: ErrAlreadySigned,
			wantMsg: "invalidating the existing signature",
		},
		{
			name:    "source account",
			entry:   entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 42),
			wantErr: ErrUnsupportedCredentials,
			wantMsg: "no address arm to upgrade",
		},
		{
			name:    "delegates arm",
			entry:   entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42),
			wantErr: ErrUnsupportedCredentials,
			wantMsg: "already address-bound",
		},
		{
			name: "unknown arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
			},
			wantErr: ErrUnsupportedCredentials,
		},
		{
			name:    "empty address arm",
			entry:   emptyArm,
			wantMsg: "address credentials arm is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UpgradeToV2(tt.entry)
			if err == nil {
				t.Fatalf("UpgradeToV2 succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected sentinel %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: upgrade to v2:") {
				t.Errorf("error %q is not wrapped as expected", err)
			}
			if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
				t.Error("UpgradeToV2 returned an entry alongside an error")
			}
		})
	}
}

func TestUpgradeToV2DoesNotMutateItsInput(t *testing.T) {
	legacy := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
	before, err := legacy.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	upgraded, err := UpgradeToV2(legacy)
	if err != nil {
		t.Fatalf("UpgradeToV2 returned an unexpected error: %v", err)
	}

	after, err := legacy.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshalling: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("UpgradeToV2 mutated its input\n before %x\n  after %x", before, after)
	}
	if legacy.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddress {
		t.Error("the caller's entry had its credentials arm changed")
	}

	upgraded.Credentials.AddressV2.Nonce = 9999
	upgraded.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	rechecked, err := legacy.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshalling: %v", err)
	}
	if !bytes.Equal(before, rechecked) {
		t.Error("the upgraded entry still shares memory with the input")
	}
}
