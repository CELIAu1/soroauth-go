package rpcfixture

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testMetadata() Metadata {
	return Metadata{
		RPCVersion:        "test-rpc/1.0",
		ProtocolVersion:   29,
		NetworkPassphrase: "Test SDF Network ; September 2015",
		LatestLedger:      1234,
		RecordedAt:        "2026-10-21T00:00:00Z",
	}
}

func TestRecorderCapturesARealExchange(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request: %v", err)
			return
		}
		var request rpcRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		if request.Method != "getLatestLedger" {
			t.Errorf("method = %q, want getLatestLedger", request.Method)
		}
		if _, err := w.Write([]byte(`{"jsonrpc":"2.0","id":7,"result":{"sequence":1234,"id":"deadbeef"}}`)); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	defer server.Close()

	recorder := NewRecorder(server.Client().Transport)
	client := &http.Client{Transport: recorder}
	response, err := client.Post(server.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"getLatestLedger","params":{}}`))
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("closing response: %v", err)
	}
	if !bytes.Contains(body, []byte(`"sequence":1234`)) {
		t.Fatalf("response = %s, want recorded sequence", body)
	}
	if requests != 1 {
		t.Fatalf("server saw %d requests, want 1", requests)
	}

	exchanges := recorder.Snapshot()
	if len(exchanges) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(exchanges))
	}
	if exchanges[0].Method != "getLatestLedger" {
		t.Fatalf("method = %q", exchanges[0].Method)
	}
	if string(exchanges[0].Params) != "{}" {
		t.Fatalf("params = %s, want {}", exchanges[0].Params)
	}
	if string(exchanges[0].Result) != `{"sequence":1234,"id":"deadbeef"}` {
		t.Fatalf("result = %s", exchanges[0].Result)
	}
	if _, err := recorder.Fixture(testMetadata()); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
}

func TestReplayerAnswersTheRecordedBytesAndRefusesARepeat(t *testing.T) {
	fixture := Fixture{
		SchemaVersion: SchemaVersion,
		Metadata:      testMetadata(),
		Exchanges: []Exchange{{
			Method: "getLatestLedger",
			Params: json.RawMessage(`{}`),
			Result: json.RawMessage(`{"sequence":1234,"id":"deadbeef"}`),
		}},
	}
	replayer, err := NewReplayer(fixture)
	if err != nil {
		t.Fatalf("building replayer: %v", err)
	}
	client := &http.Client{Transport: replayer}
	response, err := client.Post("https://fixture.invalid", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"getLatestLedger","params":{}}`))
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("closing response: %v", err)
	}
	want := `{"jsonrpc":"2.0","id":7,"result":{"sequence":1234,"id":"deadbeef"}}`
	if string(body) != want {
		t.Fatalf("response = %s, want %s", body, want)
	}
	if unused := replayer.Unused(); len(unused) != 0 {
		t.Fatalf("unused = %v, want none", unused)
	}
	if _, err := client.Post("https://fixture.invalid", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":8,"method":"getLatestLedger","params":{}}`)); err == nil {
		t.Fatal("second request was answered from a consumed exchange")
	}
}

func TestReplayerRefusesAMismatchedRequest(t *testing.T) {
	fixture := Fixture{
		SchemaVersion: SchemaVersion,
		Metadata:      testMetadata(),
		Exchanges: []Exchange{{
			Method: "getLatestLedger",
			Params: json.RawMessage(`{}`),
			Result: json.RawMessage(`{"sequence":1234}`),
		}},
	}
	replayer, err := NewReplayer(fixture)
	if err != nil {
		t.Fatalf("building replayer: %v", err)
	}
	client := &http.Client{Transport: replayer}
	_, err = client.Post("https://fixture.invalid", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"getNetwork","params":{}}`))
	if err == nil {
		t.Fatal("mismatched method was accepted")
	}
	if !strings.Contains(err.Error(), `no recorded exchange for method "getNetwork"`) {
		t.Fatalf("error = %v, want a named mismatch", err)
	}
	if len(replayer.Mismatches()) != 1 {
		t.Fatalf("mismatches = %v, want one", replayer.Mismatches())
	}
}

func TestReplayerPreservesAnRPCError(t *testing.T) {
	fixture := Fixture{
		SchemaVersion: SchemaVersion,
		Metadata:      testMetadata(),
		Exchanges: []Exchange{{
			Method: "simulateTransaction",
			Params: json.RawMessage(`{"transaction":"AAAA"}`),
			Error:  &RPCError{Code: -32602, Message: "invalid transaction", Data: json.RawMessage(`{"detail":"bad"}`)},
		}},
	}
	replayer, err := NewReplayer(fixture)
	if err != nil {
		t.Fatalf("building replayer: %v", err)
	}
	client := &http.Client{Transport: replayer}
	response, err := client.Post("https://fixture.invalid", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"simulateTransaction","params":{"transaction":"AAAA"}}`))
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	defer response.Body.Close()
	var decoded rpcResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if decoded.Error == nil || decoded.Error.Code != -32602 || decoded.Error.Message != "invalid transaction" {
		t.Fatalf("error = %+v, want the recorded error", decoded.Error)
	}
}

func TestFixtureFileRoundTripAndValidation(t *testing.T) {
	fixture := Fixture{
		SchemaVersion: SchemaVersion,
		Metadata:      testMetadata(),
		Exchanges: []Exchange{{
			Method: "getLatestLedger",
			Params: json.RawMessage(`{}`),
			Result: json.RawMessage(`{"sequence":1234}`),
		}},
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := fixture.WriteFile(path); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	if loaded.Metadata != fixture.Metadata {
		t.Fatalf("metadata = %+v, want %+v", loaded.Metadata, fixture.Metadata)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	raw = bytes.Replace(raw, []byte(`"latest_ledger": 1234`), []byte(`"latest_ledger": 0`), 1)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("rewriting fixture: %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("fixture with no ledger was accepted")
	}
}

func TestRecorderRefusesANonJSONBody(t *testing.T) {
	recorder := NewRecorder(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport was called for a non-JSON request")
		return nil, nil
	}))
	request := httptest.NewRequest(http.MethodPost, "https://fixture.invalid", strings.NewReader("not json"))
	if _, err := recorder.RoundTrip(request); err == nil {
		t.Fatal("non-JSON request was recorded")
	}
}

func TestRecorderIsSafeForConcurrentRequests(t *testing.T) {
	var mu sync.Mutex
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"sequence":1}}`))
	}))
	defer server.Close()
	recorder := NewRecorder(server.Client().Transport)
	client := &http.Client{Transport: recorder}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := client.Post(server.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"getLatestLedger","params":{}}`))
			if err != nil {
				t.Errorf("posting: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}()
	}
	wg.Wait()
	if got := len(recorder.Snapshot()); got != 8 {
		t.Fatalf("recorded %d exchanges, want 8", got)
	}
	if calls != 8 {
		t.Fatalf("server saw %d calls, want 8", calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
