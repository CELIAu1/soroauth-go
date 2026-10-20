// Package fireblocks provides a Signer backed by Fireblocks' raw-signing API.
//
// Fireblocks is an institutional custody platform that provides asynchronous
// signing with human approval flows. This signer implements the Fireblocks API
// as documented at https://developers.fireblocks.com/reference/
//
// This package is unaudited. The signer's security depends on the Fireblocks
// service and the policies configured there. A rejection by a human approver
// is returned as a distinct, matchable error (ErrHumanRejected).
package fireblocks

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const (
	defaultFireblocksBaseURL = "https://api.fireblocks.io"
	defaultFireblocksTimeout = 60 * time.Second
	maxFireblocksResponse    = 1 << 20
)

// ErrHumanRejected is returned when a human approver rejects the signing
// request in Fireblocks. This is an expected outcome, not a transport fault.
var ErrHumanRejected = errors.New("fireblocks: signing rejected by human approver")

// FireblocksConfig configures a FireblocksSigner.
type FireblocksConfig struct {
	// BaseURL is the Fireblocks API base URL. Empty defaults to
	// "https://api.fireblocks.io".
	BaseURL string

	// APIKey is the Fireblocks API key. Required.
	APIKey string

	// PrivateKey is the API private key (base64-encoded Ed25519 private key).
	// Used to sign requests. Required.
	PrivateKey string

	// VaultAccountID is the Fireblocks vault account ID. Required.
	VaultAccountID string

	// AssetID is the Fireblocks asset ID for the key (e.g., "XLM_TEST" for
	// Stellar testnet, "XLM" for mainnet). Required.
	AssetID string

	// Address is the G... account address the key signs for. Required.
	// NewFireblocksSigner refuses a key whose public key derives a different
	// address.
	Address string

	// HTTPClient is used for every request. Empty means a client with a
	// 60-second timeout.
	HTTPClient *http.Client

	// ApprovalTimeout is the maximum time to wait for human approval.
	// If exceeded, the request is cancelled and ErrHumanRejected is returned.
	// Default is 5 minutes.
	ApprovalTimeout time.Duration
}

// FireblocksSigner is a Signer backed by Fireblocks' API: the private key
// lives in Fireblocks and never reaches this process. Signing is asynchronous
// and requires human approval.
//
// It produces the built-in classic-account signature shape — a vector holding
// one {public_key, signature} map, the same shape NewEd25519Signer produces.
type FireblocksSigner struct {
	baseURL         *url.URL
	apiKey          string
	privateKey      ed25519.PrivateKey
	vaultAccountID  string
	assetID         string
	address         string
	client          *http.Client
	approvalTimeout time.Duration
	rawPublicKey    []byte // 32-byte Ed25519 public key
}

// NewFireblocksSigner validates cfg, reads the signing key's public key from
// Fireblocks, and returns a Signer that signs through the Fireblocks API.
//
// It performs one network round trip to verify the key, so it takes a context.
// A failure to authenticate surfaces as an error, a missing key as an error,
// and a key of the wrong type as an error.
func NewFireblocksSigner(ctx context.Context, cfg FireblocksConfig) (*FireblocksSigner, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("fireblocks: API key is required")
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("fireblocks: private key is required")
	}
	if cfg.VaultAccountID == "" {
		return nil, fmt.Errorf("fireblocks: vault account ID is required")
	}
	if cfg.AssetID == "" {
		return nil, fmt.Errorf("fireblocks: asset ID is required")
	}
	if _, err := strkey.Decode(strkey.VersionByteAccountID, cfg.Address); err != nil {
		return nil, fmt.Errorf("fireblocks: %w", err)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultFireblocksBaseURL
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: parsing base URL: %w", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("fireblocks: base URL %q must be absolute", baseURL)
	}

	privateKey, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: decode private key: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("fireblocks: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultFireblocksTimeout}
	}

	approvalTimeout := cfg.ApprovalTimeout
	if approvalTimeout == 0 {
		approvalTimeout = 5 * time.Minute
	}

	s := &FireblocksSigner{
		baseURL:         parsedURL,
		apiKey:          cfg.APIKey,
		privateKey:      privateKey,
		vaultAccountID:  cfg.VaultAccountID,
		assetID:         cfg.AssetID,
		address:         cfg.Address,
		client:          client,
		approvalTimeout: approvalTimeout,
	}

	// Verify the key and get its Ed25519 public key
	rawPubKey, err := s.verifyKey(ctx)
	if err != nil {
		return nil, err
	}
	s.rawPublicKey = rawPubKey

	return s, nil
}

// verifyKey calls Fireblocks to get the key details and verifies the Ed25519
// public key matches the configured address.
func (s *FireblocksSigner) verifyKey(ctx context.Context) ([]byte, error) {
	// Fireblocks doesn't have a direct "get key" endpoint for raw signing.
	// We verify by attempting a test signature or by using the vault account info.
	// For this implementation, we'll use the vault account endpoint to verify.
	path := fmt.Sprintf("/v1/vault/accounts/%s", s.vaultAccountID)
	resp, err := s.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: get vault account: %w", err)
	}

	var accountResp struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		CustomerRef string `json:"customerRef"`
		Assets      []struct {
			ID      string `json:"id"`
			Address string `json:"address,omitempty"` // For UTXO, this is the address
		} `json:"assets"`
	}
	if err := json.Unmarshal(resp, &accountResp); err != nil {
		return nil, fmt.Errorf("fireblocks: decode vault account response: %w", err)
	}

	// Find the asset and extract the public key
	// For Stellar, the asset address is the public key
	var rawPubKey []byte
	for _, asset := range accountResp.Assets {
		if asset.ID == s.assetID {
			if asset.Address != "" {
				raw, err := strkey.Decode(strkey.VersionByteAccountID, asset.Address)
				if err != nil {
					return nil, fmt.Errorf("fireblocks: decode asset address: %w", err)
				}
				rawPubKey = raw
				break
			}
		}
	}

	if rawPubKey == nil {
		return nil, fmt.Errorf("fireblocks: asset %q not found in vault account %q", s.assetID, s.vaultAccountID)
	}

	if len(rawPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("fireblocks: public key is %d bytes, want %d", len(rawPubKey), ed25519.PublicKeySize)
	}

	// Verify the address matches
	derived, err := strkey.Encode(strkey.VersionByteAccountID, rawPubKey)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: encode public key address: %w", err)
	}
	if derived != s.address {
		return nil, fmt.Errorf("fireblocks: key derives %s, configured address is %s: %w",
			derived, s.address, soroauth.ErrSignerAddressMismatch)
	}

	return rawPubKey, nil
}

// Address returns the G... account this signer signs for.
func (s *FireblocksSigner) Address() string { return s.address }

// Sign builds the preimage's payload hash, submits it to Fireblocks for
// signing, waits for human approval (with timeout), verifies the signature,
// and returns the classic-account signature shape.
func (s *FireblocksSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: sign: %w", err)
	}
	if s.rawPublicKey == nil {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: sign: %w", soroauth.ErrMissingSigner)
	}

	// Verify the payload matches the preimage
	expected, err := soroauth.Payload(preimage)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: sign: %w", err)
	}
	if !equal32(payload, expected) {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: sign: payload mismatch: %w", soroauth.ErrSignatureMismatch)
	}

	// Create a signing request
	// Fireblocks raw signing uses the /v1/transactions endpoint with
	// operation: "RAW" and extraParameters.rawMessageData
	payloadB64 := base64.StdEncoding.EncodeToString(payload[:])

	request := map[string]any{
		"assetId":   s.assetID,
		"source":    map[string]any{"type": "VAULT_ACCOUNT", "id": s.vaultAccountID},
		"operation": "RAW",
		"amount":    "0", // Not used for raw signing
		"extraParameters": map[string]any{
			"rawMessageData": map[string]any{
				"messages": []map[string]any{
					{
						"content":     payloadB64,
						"bip44Change": 0, // Not used for Ed25519
					},
				},
			},
		},
	}

	// Submit the transaction
	resp, err := s.do(ctx, http.MethodPost, "/v1/transactions", request)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: submit transaction: %w", err)
	}

	var txResp struct {
		ID     string `json:"id"`
		Status string `json:"status"` // "SUBMITTED", "PENDING_AUTHORIZATION", etc.
	}
	if err := json.Unmarshal(resp, &txResp); err != nil {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: decode transaction response: %w", err)
	}

	if txResp.ID == "" {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: no transaction ID returned")
	}

	// Wait for the transaction to complete (human approval)
	signature, err := s.waitForSignature(ctx, txResp.ID)
	if err != nil {
		return xdr.ScVal{}, err
	}

	// Verify the signature
	if !ed25519.Verify(s.rawPublicKey, payload[:], signature) {
		return xdr.ScVal{}, fmt.Errorf("fireblocks: sign: %w", soroauth.ErrSignatureMismatch)
	}

	return soroauth.Ed25519SignatureScVal(s.rawPublicKey, signature)
}

// waitForSignature polls the transaction status until it completes or times out.
func (s *FireblocksSigner) waitForSignature(ctx context.Context, txID string) ([]byte, error) {
	// Create a context with the approval timeout
	pollCtx, cancel := context.WithTimeout(ctx, s.approvalTimeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pollCtx.Done():
			// Try to cancel the transaction in Fireblocks
			_ = s.cancelTransaction(context.Background(), txID)
			if errors.Is(pollCtx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("fireblocks: approval timeout: %w", ErrHumanRejected)
			}
			return nil, fmt.Errorf("fireblocks: wait for signature: %w", pollCtx.Err())

		case <-ticker.C:
			resp, err := s.do(pollCtx, http.MethodGet, "/v1/transactions/"+txID, nil)
			if err != nil {
				continue // Keep polling on transient errors
			}

			var txResp struct {
				ID             string `json:"id"`
				Status         string `json:"status"` // "COMPLETED", "FAILED", "REJECTED", "PENDING_AUTHORIZATION", etc.
				SignedMessages []struct {
					Signature string `json:"signature"` // base64 Ed25519 signature
				} `json:"signedMessages"`
				ErrorDescription string `json:"errorDescription,omitempty"`
			}
			if err := json.Unmarshal(resp, &txResp); err != nil {
				continue
			}

			switch txResp.Status {
			case "COMPLETED":
				if len(txResp.SignedMessages) == 0 {
					return nil, fmt.Errorf("fireblocks: transaction completed but no signature")
				}
				sig, err := base64.StdEncoding.DecodeString(txResp.SignedMessages[0].Signature)
				if err != nil {
					return nil, fmt.Errorf("fireblocks: decode signature: %w", err)
				}
				if len(sig) != ed25519.SignatureSize {
					return nil, fmt.Errorf("fireblocks: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
				}
				return sig, nil

			case "FAILED", "REJECTED", "BLOCKED":
				// Check if it was a human rejection
				if txResp.ErrorDescription != "" {
					return nil, fmt.Errorf("%w: %s", ErrHumanRejected, txResp.ErrorDescription)
				}
				return nil, fmt.Errorf("%w: transaction %s", ErrHumanRejected, txResp.Status)

			case "PENDING_AUTHORIZATION", "PENDING_3RD_PARTY", "PENDING_SIGNING", "SUBMITTED":
				// Still waiting, continue polling
				continue

			default:
				// Unknown status, continue polling
				continue
			}
		}
	}
}

// cancelTransaction attempts to cancel a pending transaction.
func (s *FireblocksSigner) cancelTransaction(ctx context.Context, txID string) error {
	_, err := s.do(ctx, http.MethodPost, "/v1/transactions/"+txID+"/cancel", nil)
	return err
}

// do performs a request to the Fireblocks API with authentication.
// Fireblocks uses a JWT-like authentication where the request is signed with
// the Ed25519 private key and the signature is included in the Authorization header.
func (s *FireblocksSigner) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var bodyReader io.Reader
	var bodyBytes []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("fireblocks: encode request: %w", err)
		}
		bodyBytes = encoded
		bodyReader = bytes.NewReader(encoded)
	}

	endpoint := *s.baseURL
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: build request: %w", err)
	}

	// Fireblocks authentication: sign the request
	// The signature is over: method + path + body + timestamp
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	message := method + "\n" + path + "\n" + string(bodyBytes) + "\n" + timestamp
	sig := ed25519.Sign(s.privateKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("Authorization", "Bearer "+sigB64)
	req.Header.Set("X-Timestamp", timestamp)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: do request: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxFireblocksResponse)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("fireblocks: read response: %w", err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return respBody, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("fireblocks: %s %s: HTTP %d: %w", method, path, resp.StatusCode, soroauth.ErrVaultUnauthorized)
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("fireblocks: %s %s: HTTP %d: not found", method, path, resp.StatusCode)
	default:
		return nil, fmt.Errorf("fireblocks: %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(respBody))
	}
}

func equal32(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compile-time check
var _ soroauth.Signer = (*FireblocksSigner)(nil)
