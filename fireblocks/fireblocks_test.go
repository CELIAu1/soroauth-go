// Package fireblocks provides a Signer backed by Fireblocks' raw-signing API.
package fireblocks

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
	"github.com/stellar/go-stellar-sdk/strkey"
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

func testEd25519PrivateKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey
}

func testAddressForPublicKey(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	address, err := strkey.Encode(strkey.VersionByteAccountID, publicKey)
	if err != nil {
		t.Fatalf("encoding test public key: %v", err)
	}
	return address
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

type mockFireblocksServer struct {
	server             *httptest.Server
	testAddress        string
	testPrivKey        ed25519.PrivateKey
	testPubKey         ed25519.PublicKey
	capturedPayload    [32]byte
	capturedPayloadB64 string
	txID               string
	requireApproval    bool
	approvalRejected   bool
	blocked            chan struct{}
}

func newMockFireblocksServer(t *testing.T, testAddress string, testPrivKey ed25519.PrivateKey, testPubKey ed25519.PublicKey) *mockFireblocksServer {
	m := &mockFireblocksServer{
		testAddress: testAddress,
		testPrivKey: testPrivKey,
		testPubKey:  testPubKey,
		blocked:     make(chan struct{}),
	}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GET /v1/vault/accounts/:id - verify key
		if r.Method == http.MethodGet && r.URL.Path == "/v1/vault/accounts/test-vault" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":   "test-vault",
				"name": "Test Vault",
				"assets": []map[string]any{
					{
						"id":      "XLM_TEST",
						"address": m.testAddress,
					},
				},
			})
			return
		}

		// POST /v1/transactions - submit transaction
		if r.Method == http.MethodPost && r.URL.Path == "/v1/transactions" {
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			// Extract the payload from the request
			extraParams := req["extraParameters"].(map[string]any)
			rawMsgData := extraParams["rawMessageData"].(map[string]any)
			messages := rawMsgData["messages"].([]any)
			firstMsg := messages[0].(map[string]any)
			m.capturedPayloadB64 = firstMsg["content"].(string)
			payloadBytes, _ := base64.StdEncoding.DecodeString(m.capturedPayloadB64)
			copy(m.capturedPayload[:], payloadBytes)

			// Generate a transaction ID
			m.txID = "tx-" + base64.URLEncoding.EncodeToString([]byte("test-tx-id"))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":     m.txID,
				"status": "PENDING_AUTHORIZATION",
			})
			return
		}

		// GET /v1/transactions/:id - poll for status
		if r.Method == http.MethodGet && r.URL.Path == "/v1/transactions/"+m.txID {
			w.Header().Set("Content-Type", "application/json")
			if m.requireApproval {
				select {
				case <-m.blocked:
				}
			}
			if m.approvalRejected {
				json.NewEncoder(w).Encode(map[string]any{
					"id":               m.txID,
					"status":           "REJECTED",
					"errorDescription": "User rejected the transaction",
				})
				return
			}
			// Sign the captured payload
			sigB64 := signPayload(m.testPrivKey, m.capturedPayload)
			json.NewEncoder(w).Encode(map[string]any{
				"id":     m.txID,
				"status": "COMPLETED",
				"signedMessages": []map[string]any{
					{
						"signature": sigB64,
					},
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	return m
}

func (m *mockFireblocksServer) Close() {
	m.server.Close()
	close(m.blocked)
}

func (m *mockFireblocksServer) URL() string {
	return m.server.URL
}

func (m *mockFireblocksServer) Client() *http.Client {
	return m.server.Client()
}

func TestNewFireblocksSignerInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  FireblocksConfig
	}{
		{"missing API key", FireblocksConfig{PrivateKey: "a", VaultAccountID: "v", AssetID: "XLM_TEST", Address: "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"}},
		{"missing private key", FireblocksConfig{APIKey: "k", VaultAccountID: "v", AssetID: "XLM_TEST", Address: "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"}},
		{"missing vault account", FireblocksConfig{APIKey: "k", PrivateKey: "a", AssetID: "XLM_TEST", Address: "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"}},
		{"missing asset ID", FireblocksConfig{APIKey: "k", PrivateKey: "a", VaultAccountID: "v", Address: "GDUNOVSA72VVX7DBVVVQYUPQQSBHN7JYNASGAL4SNO7MDZPY25FTB7QN"}},
		{"invalid address", FireblocksConfig{APIKey: "k", PrivateKey: "a", VaultAccountID: "v", AssetID: "XLM_TEST", Address: "invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFireblocksSigner(context.Background(), tt.cfg)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestFireblocksSignerSuccess(t *testing.T) {
	_, testPubKey := testEd25519Keypair("fireblocks-test-key")
	testAddress := testAddressForPublicKey(t, testPubKey)

	mock := newMockFireblocksServer(t, testAddress, testEd25519PrivateKey("fireblocks-test-key"), testPubKey)
	defer mock.Close()

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

	cfg := FireblocksConfig{
		BaseURL:         mock.URL(),
		APIKey:          "test-api-key",
		PrivateKey:      base64.StdEncoding.EncodeToString(testEd25519PrivateKey("fireblocks-api-key")),
		VaultAccountID:  "test-vault",
		AssetID:         "XLM_TEST",
		Address:         testAddress,
		HTTPClient:      mock.Client(),
		ApprovalTimeout: 10 * time.Second,
	}

	signer, err := NewFireblocksSigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFireblocksSigner: %v", err)
	}

	if signer.Address() != testAddress {
		t.Errorf("Address() = %q, want %q", signer.Address(), testAddress)
	}

	preimage, payload = testPreimagePayload(t, entry)

	sigVal, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify the captured payload matches
	if mock.capturedPayloadB64 == "" {
		t.Fatal("no payload captured by mock server")
	}
	payloadBytes, _ := base64.StdEncoding.DecodeString(mock.capturedPayloadB64)
	var sentPayload [32]byte
	copy(sentPayload[:], payloadBytes)
	if sentPayload != payload {
		t.Errorf("payload sent to Fireblocks (%x) does not match expected payload (%x)", sentPayload, payload)
	}

	sigVal, err = signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	sigBytes := extractSignatureBytes(sigVal)
	if len(sigBytes) != 64 {
		t.Errorf("signature size: %d, want 64", len(sigBytes))
	}

	// Verify using the public key from the test address (same as signer's rawPublicKey)
	rawPubKey, err := strkey.Decode(strkey.VersionByteAccountID, testAddress)
	if err != nil {
		t.Fatalf("decode test address: %v", err)
	}
	if !ed25519.Verify(rawPubKey, payload[:], sigBytes) {
		t.Error("signature verification failed")
	}
}

func TestFireblocksSignerHumanRejected(t *testing.T) {
	testPrivKey, _ := testEd25519Keypair("fireblocks-test-key")
	testPrivKeyB64 := base64.StdEncoding.EncodeToString(testPrivKey)

	testPrivKeyForMock := testEd25519PrivateKey("fireblocks-test-key")
	_, testPubKey := testEd25519Keypair("fireblocks-test-key")
	testAddress := testAddressForPublicKey(t, testPubKey)

	mock := newMockFireblocksServer(t, testAddress, testPrivKeyForMock, testPubKey)
	mock.approvalRejected = true
	defer mock.Close()

	cfg := FireblocksConfig{
		BaseURL:         mock.URL(),
		APIKey:          "test-api-key",
		PrivateKey:      testPrivKeyB64,
		VaultAccountID:  "test-vault",
		AssetID:         "XLM_TEST",
		Address:         testAddress,
		HTTPClient:      mock.Client(),
		ApprovalTimeout: 10 * time.Second,
	}

	signer, err := NewFireblocksSigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFireblocksSigner: %v", err)
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
		t.Error("expected error for human rejection")
	}
	if !errors.Is(err, ErrHumanRejected) {
		t.Errorf("expected ErrHumanRejected, got %v", err)
	}
}

func TestFireblocksSignerContextCancellation(t *testing.T) {
	testPrivKey, _ := testEd25519Keypair("fireblocks-test-key")
	testPrivKeyB64 := base64.StdEncoding.EncodeToString(testPrivKey)

	testPrivKeyForMock := testEd25519PrivateKey("fireblocks-test-key")
	_, testPubKey := testEd25519Keypair("fireblocks-test-key")
	testAddress := testAddressForPublicKey(t, testPubKey)

	mock := newMockFireblocksServer(t, testAddress, testPrivKeyForMock, testPubKey)
	mock.requireApproval = true
	defer mock.Close()

	cfg := FireblocksConfig{
		BaseURL:         mock.URL(),
		APIKey:          "test-api-key",
		PrivateKey:      testPrivKeyB64,
		VaultAccountID:  "test-vault",
		AssetID:         "XLM_TEST",
		Address:         testAddress,
		HTTPClient:      mock.Client(),
		ApprovalTimeout: 10 * time.Second,
	}

	signer, err := NewFireblocksSigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFireblocksSigner: %v", err)
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

	_, err = signer.Sign(ctx, preimage, payload)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestFireblocksSignerPayloadMismatch(t *testing.T) {
	testPrivKey, _ := testEd25519Keypair("fireblocks-test-key")
	testPrivKeyB64 := base64.StdEncoding.EncodeToString(testPrivKey)

	testPrivKeyForMock := testEd25519PrivateKey("fireblocks-test-key")
	_, testPubKey := testEd25519Keypair("fireblocks-test-key")
	testAddress := testAddressForPublicKey(t, testPubKey)

	mock := newMockFireblocksServer(t, testAddress, testPrivKeyForMock, testPubKey)
	defer mock.Close()

	cfg := FireblocksConfig{
		BaseURL:         mock.URL(),
		APIKey:          "test-api-key",
		PrivateKey:      testPrivKeyB64,
		VaultAccountID:  "test-vault",
		AssetID:         "XLM_TEST",
		Address:         testAddress,
		HTTPClient:      mock.Client(),
		ApprovalTimeout: 10 * time.Second,
	}

	signer, err := NewFireblocksSigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFireblocksSigner: %v", err)
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

func TestFireblocksSignerConformance(t *testing.T) {
	_, testPubKey := testEd25519Keypair("fireblocks-test-key")
	testAddress := testAddressForPublicKey(t, testPubKey)

	testPrivKeyForMock := testEd25519PrivateKey("fireblocks-test-key")

	mock := newMockFireblocksServer(t, testAddress, testPrivKeyForMock, testPubKey)
	defer mock.Close()

	cfg := FireblocksConfig{
		BaseURL:         mock.URL(),
		APIKey:          "test-api-key",
		PrivateKey:      base64.StdEncoding.EncodeToString(testEd25519PrivateKey("fireblocks-api-key")),
		VaultAccountID:  "test-vault",
		AssetID:         "XLM_TEST",
		Address:         testAddress,
		HTTPClient:      mock.Client(),
		ApprovalTimeout: 10 * time.Second,
	}

	signer, err := NewFireblocksSigner(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFireblocksSigner: %v", err)
	}

	signertest.Run(t, signertest.Config{
		Signer:        signer,
		Deterministic: false,
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
