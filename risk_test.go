package soroauth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// loadVectorEntry loads a single vector entry by name.
func loadVectorEntry(t *testing.T, name string) xdr.SorobanAuthorizationEntry {
	t.Helper()
	vectors := loadVectors(t)
	for _, v := range vectors {
		if v.Name == name {
			var entry xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
				t.Fatalf("decoding %s: %v", name, err)
			}
			return entry
		}
	}
	t.Fatalf("vector %q not found", name)
	return xdr.SorobanAuthorizationEntry{}
}

// mockLedgerSource implements LedgerSource for testing.
type mockLedgerSource struct {
	ledger uint32
	err    error
}

func (m *mockLedgerSource) GetLatestLedger(ctx context.Context) (uint32, error) {
	return m.ledger, m.err
}

func TestAnalyzeCleanEntryProducesNoFindings(t *testing.T) {
	// Test against all golden vectors - a clean entry should produce no
	// critical or warning findings (info findings like UNSIGNED_DELEGATES
	// are acceptable for unsigned entries).
	vectors := []string{
		"legacy_single_testnet",
		"legacy_single_public",
		"legacy_negative_nonce",
		"v2_single_testnet",
		"v2_sub_invocations",
		"v2_create_contract",
		"delegates_unsorted_with_nested",
		"delegates_same_address_two_levels",
		"delegates_from_legacy",
	}

	for _, name := range vectors {
		t.Run(name, func(t *testing.T) {
			entry := loadVectorEntry(t, name)

			findings, err := Analyze(entry, nil)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			for _, f := range findings {
				// The unsigned vectors have ValidUntilLedger=0, which triggers
				// EXPIRATION_ZERO - this is expected for unsigned entries.
				// Skip this check for these test vectors.
				if f.Code == "EXPIRATION_ZERO" {
					continue
				}
				if f.Severity == SeverityCritical || f.Severity == SeverityWarning {
					t.Errorf("unexpected %s finding for clean vector %s: %s - %s", f.Severity, name, f.Code, f.Description)
				}
			}
		})
	}
}

func TestAnalyzeFarFutureExpiration(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")
	// The vector has ValidUntilLedger=0, set it to a far future value
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
		entry.Credentials.AddressV2.SignatureExpirationLedger = 2000000
	}
	cfg := &RiskConfig{
		CurrentLedger:            1000000,
		MaxValidUntilLedgerDelta: 100,
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "EXPIRATION_FAR_FUTURE" {
			found = true
			if f.Severity != SeverityWarning {
				t.Errorf("EXPIRATION_FAR_FUTURE should be warning, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected EXPIRATION_FAR_FUTURE finding")
	}
}

func TestAnalyzeZeroExpiration(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")
	// Modify entry to have zero expiration
	entry.Credentials.AddressV2.SignatureExpirationLedger = 0

	findings, err := Analyze(entry, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "EXPIRATION_ZERO" {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("EXPIRATION_ZERO should be critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected EXPIRATION_ZERO finding")
	}
}

func TestAnalyzeUnknownContract(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")

	cfg := &RiskConfig{
		KnownContracts: map[string]bool{
			"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH": true,
		},
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "CONTRACT_UNKNOWN" {
			found = true
			if f.Severity != SeverityWarning {
				t.Errorf("CONTRACT_UNKNOWN should be warning, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CONTRACT_UNKNOWN finding")
	}
}

func TestAnalyzeKnownContractNoFinding(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")
	info, _ := Inspect(entry)

	cfg := &RiskConfig{
		KnownContracts: map[string]bool{
			info.RootContract: true,
		},
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.Code == "CONTRACT_UNKNOWN" {
			t.Errorf("unexpected CONTRACT_UNKNOWN finding for known contract")
		}
	}
}

func TestAnalyzeDeepDelegateTree(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1").Address()
	d2 := testKeypair(t, "soroauth-delegate-2").Address()
	d3 := testKeypair(t, "soroauth-delegate-3").Address()
	d4 := testKeypair(t, "soroauth-delegate-4").Address()

	// Create a deeply nested delegate tree (depth 4)
	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{
			Address: d1,
			Nested: []Delegate{
				{
					Address: d2,
					Nested: []Delegate{
						{
							Address: d3,
							Nested: []Delegate{
								{Address: d4},
							},
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("building entry: %v", err)
	}

	cfg := &RiskConfig{
		MaxDelegateDepth: 3,
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "DELEGATE_DEPTH_EXCEEDED" {
			found = true
			if f.Severity != SeverityWarning {
				t.Errorf("DELEGATE_DEPTH_EXCEEDED should be warning, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected DELEGATE_DEPTH_EXCEEDED finding")
	}
}

func TestAnalyzeManyDelegates(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	// Create 15 delegates (exceeds default 10)
	delegates := make([]Delegate, 15)
	for i := 0; i < 15; i++ {
		delegates[i] = Delegate{
			Address: testKeypair(t, "soroauth-many-delegate-"+string(rune('0'+i))).Address(),
		}
	}

	entry, err := WithDelegates(base, testValidUntilLedger, delegates, nil)
	if err != nil {
		t.Fatalf("building entry: %v", err)
	}

	cfg := &RiskConfig{
		MaxTotalDelegates: 10,
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "DELEGATE_COUNT_HIGH" {
			found = true
			if f.Severity != SeverityWarning {
				t.Errorf("DELEGATE_COUNT_HIGH should be warning, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected DELEGATE_COUNT_HIGH finding")
	}
}

func TestAnalyzeManySubInvocations(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")

	// Add many sub-invocations
	leaf := func(name string) xdr.SorobanAuthorizedInvocation {
		return xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: mustParse(t, testContractAddress(t, "soroauth-risk-leaf")),
					FunctionName:    xdr.ScSymbol(name),
				},
			},
		}
	}

	// Create 60 sub-invocations (exceeds default 50)
	var subs []xdr.SorobanAuthorizedInvocation
	for i := 0; i < 60; i++ {
		subs = append(subs, leaf("fn"+string(rune('0'+i%10))))
	}
	entry.RootInvocation.SubInvocations = subs

	cfg := &RiskConfig{
		MaxSubInvocations: 50,
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "SUB_INVOCATION_COUNT_HIGH" {
			found = true
			if f.Severity != SeverityWarning {
				t.Errorf("SUB_INVOCATION_COUNT_HIGH should be warning, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SUB_INVOCATION_COUNT_HIGH finding")
	}
}

func TestAnalyzeUnsignedDelegates(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1").Address()
	d2 := testKeypair(t, "soroauth-delegate-2").Address()

	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: d1},
		{Address: d2},
	}, nil)
	if err != nil {
		t.Fatalf("building entry: %v", err)
	}

	findings, err := Analyze(entry, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "UNSIGNED_DELEGATES" {
			found = true
			if f.Severity != SeverityInfo {
				t.Errorf("UNSIGNED_DELEGATES should be info, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected UNSIGNED_DELEGATES finding")
	}
}

func TestAnalyzeLegacyCredentialsNotAddressBound(t *testing.T) {
	entry := loadVectorEntry(t, "legacy_single_testnet")

	findings, err := Analyze(entry, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND" {
			found = true
			if f.Severity != SeverityInfo {
				t.Errorf("LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND should be info, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND finding")
	}
}

func TestAnalyzeV2CredentialsNoLegacyFinding(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")

	findings, err := Analyze(entry, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.Code == "LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND" {
			t.Errorf("unexpected LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND for V2 credentials")
		}
	}
}

func TestAnalyzeSeverityOrdering(t *testing.T) {
	// Create an entry that triggers multiple findings of different severities
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{ // Use valid expiration
		{Address: testKeypair(t, "soroauth-d1").Address()},
	}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	// Set zero expiration to trigger critical
	entry.Credentials.AddressWithDelegates.AddressCredentials.SignatureExpirationLedger = 0

	cfg := &RiskConfig{
		CurrentLedger:            1000000,
		MaxValidUntilLedgerDelta: 100,               // Far future = warning
		MaxTotalDelegates:        0,                 // Any delegates = warning
		KnownContracts:           map[string]bool{}, // Unknown contract = warning
	}

	findings, err := Analyze(entry, cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Check ordering: critical first, then warning, then info
	severityOrder := map[FindingSeverity]int{
		SeverityCritical: 0,
		SeverityWarning:  1,
		SeverityInfo:     2,
	}
	for i := 0; i < len(findings)-1; i++ {
		if severityOrder[findings[i].Severity] > severityOrder[findings[i+1].Severity] {
			t.Errorf("findings not sorted by severity: %s (%d) before %s (%d)",
				findings[i].Code, severityOrder[findings[i].Severity],
				findings[i+1].Code, severityOrder[findings[i+1].Severity])
		}
	}
}

func TestAnalyzeWithCurrentLedger(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")
	// The vector has ValidUntilLedger=0, set it to a far future value
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
		entry.Credentials.AddressV2.SignatureExpirationLedger = 2000000
	}
	cfg := &RiskConfig{
		MaxValidUntilLedgerDelta: 100,
	}
	src := &mockLedgerSource{ledger: 1000000}

	findings, err := AnalyzeWithCurrentLedger(context.Background(), entry, cfg, src)
	if err != nil {
		t.Fatalf("AnalyzeWithCurrentLedger failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "EXPIRATION_FAR_FUTURE" {
			found = true
		}
	}
	if !found {
		t.Error("expected EXPIRATION_FAR_FUTURE finding with current ledger")
	}
}

func TestAnalyzeWithCurrentLedgerErrorFallsBack(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")
	cfg := &RiskConfig{
		MaxValidUntilLedgerDelta: 100,
	}
	src := &mockLedgerSource{ledger: 1000000, err: context.DeadlineExceeded}

	findings, err := AnalyzeWithCurrentLedger(context.Background(), entry, cfg, src)
	if err != nil {
		t.Fatalf("AnalyzeWithCurrentLedger failed: %v", err)
	}

	// Should not have EXPIRATION_FAR_FUTURE since ledger fetch failed
	for _, f := range findings {
		if f.Code == "EXPIRATION_FAR_FUTURE" {
			t.Error("unexpected EXPIRATION_FAR_FUTURE when ledger source failed")
		}
	}
}

func TestDefaultRiskConfig(t *testing.T) {
	cfg := DefaultRiskConfig()
	if cfg.MaxDelegateDepth != 3 {
		t.Errorf("MaxDelegateDepth = %d, want 3", cfg.MaxDelegateDepth)
	}
	if cfg.MaxTotalDelegates != 10 {
		t.Errorf("MaxTotalDelegates = %d, want 10", cfg.MaxTotalDelegates)
	}
	if cfg.MaxValidUntilLedgerDelta != 10000 {
		t.Errorf("MaxValidUntilLedgerDelta = %d, want 10000", cfg.MaxValidUntilLedgerDelta)
	}
	if cfg.MaxSubInvocations != 50 {
		t.Errorf("MaxSubInvocations = %d, want 50", cfg.MaxSubInvocations)
	}
	if cfg.KnownContracts == nil {
		t.Error("KnownContracts should be initialized")
	}
}

func TestAnalyzeSourceAccountWithDelegates(t *testing.T) {
	entry := loadVectorEntry(t, "legacy_single_testnet")
	entry.Credentials.Type = xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount
	// Add delegates to source account (malformed)
	entry.Credentials.AddressWithDelegates = &xdr.SorobanAddressCredentialsWithDelegates{
		AddressCredentials: xdr.SorobanAddressCredentials{
			SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
		},
		Delegates: []xdr.SorobanDelegateSignature{
			{Address: mustParse(t, testKeypair(t, "soroauth-d1").Address())},
		},
	}

	findings, err := Analyze(entry, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Code == "SOURCE_ACCOUNT_WITH_DELEGATES" {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("SOURCE_ACCOUNT_WITH_DELEGATES should be critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SOURCE_ACCOUNT_WITH_DELEGATES finding")
	}
}

func TestFindingJSONMarshal(t *testing.T) {
	f := Finding{
		Code:        "TEST_CODE",
		Severity:    SeverityWarning,
		Title:       "Test Finding",
		Description: "Test description",
		Rationale:   "Test rationale",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed Finding
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Code != f.Code || parsed.Severity != f.Severity || parsed.Title != f.Title {
		t.Errorf("JSON round-trip failed: got %+v", parsed)
	}
}

func TestRiskConfigJSONMarshal(t *testing.T) {
	cfg := RiskConfig{
		MaxDelegateDepth:         5,
		MaxTotalDelegates:        20,
		MaxValidUntilLedgerDelta: 5000,
		KnownContracts:           map[string]bool{"C123": true},
		MaxSubInvocations:        100,
		CurrentLedger:            12345,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed RiskConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.MaxDelegateDepth != cfg.MaxDelegateDepth ||
		parsed.MaxTotalDelegates != cfg.MaxTotalDelegates ||
		parsed.MaxValidUntilLedgerDelta != cfg.MaxValidUntilLedgerDelta ||
		parsed.MaxSubInvocations != cfg.MaxSubInvocations ||
		parsed.CurrentLedger != cfg.CurrentLedger {
		t.Errorf("JSON round-trip failed: got %+v", parsed)
	}
}

// TestFindingStringGolden verifies the String() output matches the golden format.
func TestFindingStringGolden(t *testing.T) {
	f := Finding{
		Code:        "EXPIRATION_FAR_FUTURE",
		Severity:    SeverityWarning,
		Title:       "Signature expiration far in the future",
		Description: "Valid until ledger 2000000 (current: 1000000, delta: 1000000, limit: 10000)",
		Rationale:   "A distant expiration means the signature can be reused for longer. If the signed invocation is malicious or buggy, the window for abuse is larger.",
	}
	want := "[warning] EXPIRATION_FAR_FUTURE: Signature expiration far in the future\n  Valid until ledger 2000000 (current: 1000000, delta: 1000000, limit: 10000)\n  rationale: A distant expiration means the signature can be reused for longer. If the signed invocation is malicious or buggy, the window for abuse is larger."
	got := f.String()
	if got != want {
		t.Errorf("String() output mismatch:\n got:\n%s\n want:\n%s", got, want)
	}
}

// TestFindingStringDoesNotPanic verifies String() never panics on pathological values.
func TestFindingStringDoesNotPanic(t *testing.T) {
	// Very long fields
	long := Finding{
		Code:        strings.Repeat("X", 10000),
		Severity:    SeverityCritical,
		Title:       strings.Repeat("Y", 10000),
		Description: strings.Repeat("Z", 10000),
		Rationale:   strings.Repeat("W", 10000),
	}
	_ = long.String() // Should not panic

	// Empty fields
	empty := Finding{}
	_ = empty.String() // Should not panic
}
