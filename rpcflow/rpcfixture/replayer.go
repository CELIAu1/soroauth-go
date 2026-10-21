package rpcfixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Replayer is an http.RoundTripper that answers requests from a Fixture.
//
// Matching is by method and JSON params. Exchanges are consumed once: replaying
// the same request twice without recording it twice is an error rather than a
// silent repeat of a stale response, because a test that makes more calls than
// the fixture describes is not testing the recorded flow.
type Replayer struct {
	mu        sync.Mutex
	fixture   Fixture
	used      []bool
	unmatched []string
}

// NewReplayer returns a Replayer for fixture.
func NewReplayer(fixture Fixture) (*Replayer, error) {
	if err := fixture.Validate(); err != nil {
		return nil, err
	}
	return &Replayer{fixture: fixture, used: make([]bool, len(fixture.Exchanges))}, nil
}

// RoundTrip implements http.RoundTripper.
func (r *Replayer) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body == nil {
		return nil, r.mismatch("request has no body")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("rpcfixture: replayer: reading request body: %w", err)
	}
	if err := request.Body.Close(); err != nil {
		return nil, fmt.Errorf("rpcfixture: replayer: closing request body: %w", err)
	}

	var envelope rpcRequest
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, r.mismatch(fmt.Sprintf("request is not JSON-RPC: %v", err))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for i, exchange := range r.fixture.Exchanges {
		if r.used[i] || exchange.Method != envelope.Method {
			continue
		}
		equal, err := jsonEqual(exchange.Params, envelope.Params)
		if err != nil {
			return nil, fmt.Errorf("rpcfixture: replayer: recorded params for %s: %w", exchange.Method, err)
		}
		if !equal {
			continue
		}
		r.used[i] = true
		return responseFor(envelope, exchange)
	}

	requestJSON, _ := json.Marshal(envelope.Params)
	message := fmt.Sprintf("no recorded exchange for method %q with params %s", envelope.Method, requestJSON)
	r.unmatched = append(r.unmatched, message)
	return nil, fmt.Errorf("rpcfixture: replayer: %s", message)
}

func (r *Replayer) mismatch(detail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unmatched = append(r.unmatched, detail)
	return fmt.Errorf("rpcfixture: replayer: %s", detail)
}

// Unused returns the methods of exchanges the replay did not consume, in
// fixture order.
func (r *Replayer) Unused() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var unused []string
	for i, exchange := range r.fixture.Exchanges {
		if !r.used[i] {
			unused = append(unused, exchange.Method)
		}
	}
	return unused
}

// Mismatches returns the requests the fixture did not describe, in the order
// they were refused.
func (r *Replayer) Mismatches() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.unmatched))
	copy(out, r.unmatched)
	return out
}

func responseFor(request rpcRequest, exchange Exchange) (*http.Response, error) {
	response := rpcResponse{JSONRPC: "2.0", ID: request.ID}
	if exchange.Error != nil {
		response.Error = exchange.Error
	} else {
		response.Result = exchange.Result
	}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("rpcfixture: replayer: encoding response: %w", err)
	}
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       nil,
	}, nil
}

func jsonEqual(a, b []byte) (bool, error) {
	var left, right any
	if err := json.Unmarshal(a, &left); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &right); err != nil {
		return false, err
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		return false, err
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftJSON, rightJSON), nil
}
