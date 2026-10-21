package rpcfixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Recorder wraps an http.RoundTripper and records every JSON-RPC exchange.
//
// The wrapped transport is used for the request, so the recorded response is
// the one the caller actually received. A non-JSON-RPC request is an error:
// silently passing it through would produce a fixture that does not describe
// the traffic the test made.
type Recorder struct {
	Base http.RoundTripper

	mu        sync.Mutex
	exchanges []Exchange
}

// NewRecorder returns a Recorder using base, or http.DefaultTransport when
// base is nil.
func NewRecorder(base http.RoundTripper) *Recorder {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Recorder{Base: base}
}

// RoundTrip implements http.RoundTripper.
func (r *Recorder) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body == nil {
		return nil, fmt.Errorf("rpcfixture: recorder: request has no body")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("rpcfixture: recorder: reading request body: %w", err)
	}
	if err := request.Body.Close(); err != nil {
		return nil, fmt.Errorf("rpcfixture: recorder: closing request body: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))

	var envelope rpcRequest
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("rpcfixture: recorder: request is not JSON-RPC: %w", err)
	}
	if envelope.Method == "" {
		return nil, fmt.Errorf("rpcfixture: recorder: request has no method")
	}

	response, err := r.Base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	responseBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("rpcfixture: recorder: reading response body: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("rpcfixture: recorder: closing response body: %w", closeErr)
	}
	response.Body = io.NopCloser(bytes.NewReader(responseBody))

	var decoded rpcResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, fmt.Errorf("rpcfixture: recorder: response is not JSON-RPC: %w", err)
	}
	exchange := Exchange{
		Method: envelope.Method,
		Params: append(json.RawMessage(nil), envelope.Params...),
	}
	if decoded.Error != nil {
		exchange.Error = &RPCError{
			Code:    decoded.Error.Code,
			Message: decoded.Error.Message,
			Data:    append(json.RawMessage(nil), decoded.Error.Data...),
		}
	} else {
		exchange.Result = append(json.RawMessage(nil), decoded.Result...)
	}

	r.mu.Lock()
	r.exchanges = append(r.exchanges, exchange)
	r.mu.Unlock()
	return response, nil
}

// Snapshot returns a copy of the exchanges recorded so far.
func (r *Recorder) Snapshot() []Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Exchange, len(r.exchanges))
	copy(out, r.exchanges)
	return out
}

// Fixture returns a validated fixture containing every recorded exchange.
func (r *Recorder) Fixture(metadata Metadata) (Fixture, error) {
	fixture := Fixture{
		SchemaVersion: SchemaVersion,
		Metadata:      metadata,
		Exchanges:     r.Snapshot(),
	}
	if err := fixture.Validate(); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}
