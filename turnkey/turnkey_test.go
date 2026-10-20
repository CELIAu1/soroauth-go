// Package turnkey provides a Signer backed by Turnkey's signing API.
package turnkey

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/signertest"
)

func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, _ := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	return kp
}

func testEd25519Keypair(label string) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte(label))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return privateKey, publicKey
}

func signPayload(privateKey ed25519.PrivateKey, payload [32]byte) string {
	sig := ed25519.Sign(privateKey, payload[:])
	return base64.StdEncoding.EncodeToString(sig)
}

func testPreimagePayload(t *testing.T, entry xdr.SorobanAuthorizationEntry) (xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	preimage, err := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	return preimage, payload
}

func TestNewTurnkeySignerInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  TurnkeyConfig
	}{
		{"missing org ID", TurnkeyConfig{PrivateKey: "a", PublicKey: "b", KeyID: "k", Address: "GABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDAB"}},
		{"missing private key", TurnkeyConfig{OrganizationID: "org", PublicKey: "b", KeyID: "k", Address: "GABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDAB"}},
		{"missing public key", TurnkeyConfig{OrganizationID: "org", PrivateKey: "a", KeyID: "k", Address: "GABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDAB"}},
		{"missing key ID", TurnkeyConfig{OrganizationID: "org", PrivateKey: "a", PublicKey: "b", Address: "GABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDAB"}},
		{"invalid address", TurnkeyConfig{OrganizationID: "org", PrivateKey: "a", PublicKey: "b", KeyID: "k", Address: "invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTurnkeySigner(context.Background(), tt.cfg)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestTurnkeySignerSuccess(t *testing.T) {
	// Use deterministic key for testing
	_, testPubKey := testEd25519Keypair("turnkey-test-key")
	testPubKeyB64 := base64.StdEncoding.EncodeToString(testPubKey)
	testAddress := "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"

	// Mock Turnkey server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate successful key verification on GET /keys/:id
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/keys/test-key-id" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"key": map[string]any{
					"type":      "ED25519",
					"publicKey": testPubKeyB64,
					"curve":     "ED25519",
				},
			})
			return
		}

		// Simulate successful signing on POST /submit
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/submit" {
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			// Extract the payload from the request and sign it with the test private key
			params := req["parameters"].(map[string]any)
			signRaw := params["signRaw"].(map[string]any)
			payloadB64 := signRaw["payload"].(string)
			payloadBytes, _ := base64.StdEncoding.DecodeString(payloadB64)
			var payload [32]byte
			copy(payload[:], payloadBytes)

			testPrivKey, _ := testEd25519Keypair("turnkey-test-key")
			sigB64 := signPayload(testPrivKey, payload)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"activity": map[string]any{
					"id":     "test-activity-id",
					"status": "ACTIVITY_STATUS_COMPLETED",
					"result": map[string]any{
						"signRaw": map[string]any{
							"signature": sigB64,
						},
					},
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := TurnkeyConfig{
		BaseURL:        server.URL,
		OrganizationID: "test-org",
		PrivateKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		KeyID:          "test-key-id",
		Address:        testAddress,
		HTTPClient:     server.Client(),
	}

	signer, err := NewTurnkeySigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTurnkeySigner: %v", err)
	}

	if signer.Address() != testAddress {
		t.Errorf("Address() = %q, want %q", signer.Address(), testAddress)
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(testAddress); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	preimage, payload := testPreimagePayload(t, entry)

	sigVal, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify the signature is the expected shape
	sigBytes := extractSignatureBytes(sigVal)
	if len(sigBytes) != 64 {
		t.Errorf("signature size: %d, want 64", len(sigBytes))
	}

	// Verify the signature matches the test public key
	if !ed25519.Verify(testPubKey, payload[:], sigBytes) {
		t.Error("signature verification failed")
	}
}

func TestTurnkeySignerPolicyDenied(t *testing.T) {
	_, testPubKey := testEd25519Keypair("turnkey-test-key")
	testPubKeyB64 := base64.StdEncoding.EncodeToString(testPubKey)
	testAddress := "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/keys/test-key-id" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"key": map[string]any{
					"type":      "ED25519",
					"publicKey": testPubKeyB64,
					"curve":     "ED25519",
				},
			})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/submit" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"activity": map[string]any{
					"id":     "test-activity-id",
					"status": "ACTIVITY_STATUS_FAILED",
					"error": map[string]any{
						"code":    "POLICY_DENIED",
						"message": "policy requires 2 approvals, got 0",
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := TurnkeyConfig{
		BaseURL:        server.URL,
		OrganizationID: "test-org",
		PrivateKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		KeyID:          "test-key-id",
		Address:        testAddress,
		HTTPClient:     server.Client(),
	}

	signer, err := NewTurnkeySigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTurnkeySigner: %v", err)
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(testAddress); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	preimage, payload := testPreimagePayload(t, entry)

	_, err = signer.Sign(context.Background(), preimage, payload)
	if err == nil {
		t.Error("expected error for policy denial")
	}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Errorf("expected ErrPolicyDenied, got %v", err)
	}
}

func TestTurnkeySignerContextCancellation(t *testing.T) {
	blocked := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow GET /keys to succeed immediately for signer construction
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/keys/test-key-id" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"key": map[string]any{
					"type":      "ED25519",
					"publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					"curve":     "ED25519",
				},
			})
			return
		}
		// Block POST /submit
		<-blocked
	}))
	defer server.Close()
	defer close(blocked)

	address := "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	cfg := TurnkeyConfig{
		BaseURL:        server.URL,
		OrganizationID: "test-org",
		PrivateKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		KeyID:          "test-key-id",
		Address:        address,
		HTTPClient:     server.Client(),
	}

	signer, err := NewTurnkeySigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTurnkeySigner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(address); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	preimage, payload := testPreimagePayload(t, entry)

	_, err = signer.Sign(ctx, preimage, payload)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestTurnkeySignerPayloadMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/keys/test-key-id" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"key": map[string]any{
					"type":      "ED25519",
					"publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					"curve":     "ED25519",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	address := "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	cfg := TurnkeyConfig{
		BaseURL:        server.URL,
		OrganizationID: "test-org",
		PrivateKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		KeyID:          "test-key-id",
		Address:        address,
		HTTPClient:     server.Client(),
	}

	signer, err := NewTurnkeySigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTurnkeySigner: %v", err)
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   func() xdr.ScAddress { a, _ := soroauth.ParseAddress(address); return a }(),
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: func() *xdr.ContractId { var c xdr.ContractId; c[0] = 1; return &c }(),
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	preimage, _ := testPreimagePayload(t, entry)
	wrongPayload := [32]byte{1, 2, 3}

	_, err = signer.Sign(context.Background(), preimage, wrongPayload)
	if err == nil {
		t.Error("expected error for payload mismatch")
	}
	if !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}
}

func extractSignatureBytes(val xdr.ScVal) []byte {
	vecPtr, ok := val.GetVec()
	if !ok || vecPtr == nil {
		return nil
	}
	vec := *vecPtr
	if len(vec) != 1 {
		return nil
	}
	m := vec[0]
	mapPtr, ok := m.GetMap()
	if !ok || mapPtr == nil {
		return nil
	}
	for _, kv := range *mapPtr {
		if kv.Key.Type == xdr.ScValTypeScvSymbol && kv.Key.Sym != nil && string(*kv.Key.Sym) == "signature" {
			if kv.Val.Type == xdr.ScValTypeScvBytes && kv.Val.Bytes != nil {
				return (*kv.Val.Bytes)[:]
			}
		}
	}
	return nil
}

func TestTurnkeySignerConformance(t *testing.T) {
	_, testPubKey := testEd25519Keypair("turnkey-test-key")
	testPubKeyB64 := base64.StdEncoding.EncodeToString(testPubKey)
	testAddress := "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"

	// Mock Turnkey server that dynamically signs any payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/keys/test-key-id" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"key": map[string]any{
					"type":      "ED25519",
					"publicKey": testPubKeyB64,
					"curve":     "ED25519",
				},
			})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/submit" {
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			params := req["parameters"].(map[string]any)
			signRaw := params["signRaw"].(map[string]any)
			payloadB64 := signRaw["payload"].(string)
			payloadBytes, _ := base64.StdEncoding.DecodeString(payloadB64)
			var payload [32]byte
			copy(payload[:], payloadBytes)

			testPrivKey, _ := testEd25519Keypair("turnkey-test-key")
			sigB64 := signPayload(testPrivKey, payload)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"activity": map[string]any{
					"id":     "test-activity-id",
					"status": "ACTIVITY_STATUS_COMPLETED",
					"result": map[string]any{
						"signRaw": map[string]any{
							"signature": sigB64,
						},
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := TurnkeyConfig{
		BaseURL:        server.URL,
		OrganizationID: "test-org",
		PrivateKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		KeyID:          "test-key-id",
		Address:        testAddress,
		HTTPClient:     server.Client(),
	}

	signer, err := NewTurnkeySigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTurnkeySigner: %v", err)
	}

	signertest.Run(t, signertest.Config{
		Signer:        signer,
		Deterministic: false, // Turnkey signatures may vary
		Verify: func(sig xdr.ScVal, payload [32]byte) error {
			sigBytes := extractSignatureBytes(sig)
			if sigBytes == nil {
				return errors.New("invalid signature format")
			}
			if !ed25519.Verify(testPubKey, payload[:], sigBytes) {
				return errors.New("signature verification failed")
			}
			return nil
		},
	})
}
