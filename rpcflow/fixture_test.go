package rpcflow_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/rpcflow"
	"github.com/soroauth/soroauth-go/rpcflow/rpcfixture"
)

func TestSimulateRecordAgainstACommittedTestnetFixture(t *testing.T) {
	fixture, err := rpcfixture.LoadFile(filepath.Join("rpcfixture", "testdata", "simulate_record_testnet.json"))
	if err != nil {
		t.Fatalf("loading the committed fixture: %v", err)
	}
	if fixture.Metadata.NetworkPassphrase != "Test SDF Network ; September 2015" {
		t.Fatalf("fixture network = %q, want testnet", fixture.Metadata.NetworkPassphrase)
	}
	if fixture.Metadata.LatestLedger == 0 || fixture.Metadata.RPCVersion == "" || fixture.Metadata.ProtocolVersion <= 0 {
		t.Fatalf("fixture metadata is incomplete: %+v", fixture.Metadata)
	}

	var request struct {
		Transaction     string `json:"transaction"`
		AuthMode        string `json:"authMode"`
		UseUpgradedAuth bool   `json:"useUpgradedAuth"`
	}
	if err := json.Unmarshal(fixture.Exchanges[0].Params, &request); err != nil {
		t.Fatalf("decoding the recorded request: %v", err)
	}
	if request.Transaction == "" || request.AuthMode != "record" {
		t.Fatalf("recorded request is not a record-mode simulation: %+v", request)
	}

	replayer, err := rpcfixture.NewReplayer(fixture)
	if err != nil {
		t.Fatalf("building the replayer: %v", err)
	}
	client := rpcclient.NewClient("https://fixture.invalid", &http.Client{Transport: replayer})

	record, err := rpcflow.SimulateRecord(context.Background(), rpcflow.RecordParams{
		Client:          client,
		EnvelopeXDR:     request.Transaction,
		UseUpgradedAuth: request.UseUpgradedAuth,
	})
	if err != nil {
		t.Fatalf("SimulateRecord against the fixture: %v", err)
	}
	if len(record.Entries) == 0 {
		t.Fatal("the recorded simulation produced no authorization entries")
	}
	if got, want := record.Entries[0].Arm, "address_v2"; got != want {
		t.Fatalf("recorded entry arm = %q, want %q", got, want)
	}
	if record.Entries[0].Entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
		t.Fatalf("recorded credential XDR type = %v, want address V2", record.Entries[0].Entry.Credentials.Type)
	}
	if unused := replayer.Unused(); len(unused) != 0 {
		t.Fatalf("fixture exchanges left unused: %v", unused)
	}
	if mismatches := replayer.Mismatches(); len(mismatches) != 0 {
		t.Fatalf("fixture requests mismatched: %v", mismatches)
	}
}
