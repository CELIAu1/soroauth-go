// Package rpcfixture records and replays Stellar RPC JSON-RPC exchanges.
//
// The recorder wraps an http.RoundTripper and stores each request's method and
// params with the response's raw result or error. The replayer is another
// http.RoundTripper, so a real rpcclient.Client can be driven offline against
// committed bytes instead of a hand-written fake. Recorded results are kept
// verbatim: the fixture is evidence of what the RPC returned, and re-encoding
// a decoded response would make the test compare against this package's
// understanding of the response rather than the response itself.
//
// Fixtures are only useful if they say what produced them. Every fixture
// carries the RPC version, the network passphrase, and the latest ledger at
// record time; Load rejects a fixture missing any of them. Recording must be
// done against testnet (or another public network) with a request that carries
// no secret. A transaction's signatures are public, but a caller recording a
// request should still inspect it before committing: this package cannot know
// which application-level fields are sensitive.
package rpcfixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// SchemaVersion is the version of the on-disk fixture document.
const SchemaVersion = 1

// Metadata describes where and when a fixture was recorded.
type Metadata struct {
	RPCVersion        string `json:"rpc_version"`
	ProtocolVersion   int    `json:"protocol_version"`
	NetworkPassphrase string `json:"network_passphrase"`
	LatestLedger      uint32 `json:"latest_ledger"`
	RecordedAt        string `json:"recorded_at,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Exchange is one JSON-RPC request and the response the RPC gave it.
//
// Params and Result are raw JSON, not decoded values. A replay writes Result
// back byte for byte; Error, when set, is written as the response's error
// member instead.
type Exchange struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// Fixture is a committed set of exchanges and their provenance.
type Fixture struct {
	SchemaVersion int        `json:"schema_version"`
	Metadata      Metadata   `json:"metadata"`
	Exchanges     []Exchange `json:"exchanges"`
}

// Validate refuses a fixture that cannot be replayed or cannot be trusted to
// say where it came from.
func (f Fixture) Validate() error {
	if f.SchemaVersion != SchemaVersion {
		return fmt.Errorf("rpcfixture: unsupported schema_version %d, want %d", f.SchemaVersion, SchemaVersion)
	}
	if f.Metadata.RPCVersion == "" {
		return fmt.Errorf("rpcfixture: metadata.rpc_version is required")
	}
	if f.Metadata.ProtocolVersion <= 0 {
		return fmt.Errorf("rpcfixture: metadata.protocol_version must be positive")
	}
	if f.Metadata.NetworkPassphrase == "" {
		return fmt.Errorf("rpcfixture: metadata.network_passphrase is required")
	}
	if f.Metadata.LatestLedger == 0 {
		return fmt.Errorf("rpcfixture: metadata.latest_ledger must be positive")
	}
	if len(f.Exchanges) == 0 {
		return fmt.Errorf("rpcfixture: fixture has no exchanges")
	}
	for i, exchange := range f.Exchanges {
		if exchange.Method == "" {
			return fmt.Errorf("rpcfixture: exchange %d has no method", i)
		}
		if len(exchange.Params) == 0 {
			return fmt.Errorf("rpcfixture: exchange %d (%s) has no params", i, exchange.Method)
		}
		if (len(exchange.Result) == 0) == (exchange.Error == nil) {
			return fmt.Errorf("rpcfixture: exchange %d (%s) must carry exactly one of result or error", i, exchange.Method)
		}
	}
	return nil
}

// Marshal renders a fixture as indented JSON with a trailing newline.
func (f Fixture) Marshal() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("rpcfixture: marshalling fixture: %w", err)
	}
	return append(encoded, '\n'), nil
}

// WriteFile writes a fixture atomically enough for a repository tool: it
// marshals and validates before touching the destination.
func (f Fixture) WriteFile(path string) error {
	encoded, err := f.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("rpcfixture: writing %s: %w", path, err)
	}
	return nil
}

// LoadFile reads and validates a fixture.
func LoadFile(path string) (Fixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, fmt.Errorf("rpcfixture: reading %s: %w", path, err)
	}
	var fixture Fixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		return Fixture{}, fmt.Errorf("rpcfixture: parsing %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Fixture{}, fmt.Errorf("rpcfixture: %s has trailing data", path)
	}
	if err := fixture.Validate(); err != nil {
		return Fixture{}, fmt.Errorf("%s: %w", path, err)
	}
	return fixture, nil
}
