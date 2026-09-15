package soroauth

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestExpirationAfter(t *testing.T) {
	tests := []struct {
		name         string
		latestLedger uint32
		ledgers      uint32
		want         uint32
	}{
		{name: "one ledger ahead", latestLedger: 1000, ledgers: 1, want: 1001},
		{name: "an hour of ledgers", latestLedger: 1234567, ledgers: 720, want: 1235287},
		{name: "from genesis", latestLedger: 0, ledgers: 100, want: 100},
		{
			name:         "the largest sum that still fits",
			latestLedger: math.MaxUint32 - 1,
			ledgers:      1,
			want:         math.MaxUint32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpirationAfter(tt.latestLedger, tt.ledgers)
			if err != nil {
				t.Fatalf("ExpirationAfter returned an unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExpirationAfterRejects(t *testing.T) {
	tests := []struct {
		name         string
		latestLedger uint32
		ledgers      uint32
		wantMsg      string
	}{
		{
			name:         "zero ledgers",
			latestLedger: 1000,
			ledgers:      0,
			wantMsg:      "at least 1",
		},
		{
			name:         "overflow by one",
			latestLedger: math.MaxUint32,
			ledgers:      1,
			wantMsg:      "overflows",
		},
		{
			name:         "overflow by a lot",
			latestLedger: math.MaxUint32 - 10,
			ledgers:      1000,
			wantMsg:      "overflows",
		},
		{
			name:         "both operands at the maximum",
			latestLedger: math.MaxUint32,
			ledgers:      math.MaxUint32,
			wantMsg:      "overflows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpirationAfter(tt.latestLedger, tt.ledgers)
			if err == nil {
				t.Fatalf("ExpirationAfter succeeded, returning %d", got)
			}
			if !errors.Is(err, ErrInvalidExpiration) {
				t.Errorf("error %q does not match ErrInvalidExpiration", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if got != 0 {
				t.Errorf("ExpirationAfter returned %d alongside an error, want 0", got)
			}
		})
	}
}

// TestExpirationAfterNeverWraps is the property the overflow check exists for:
// wrapping would turn a long lifetime into an expiration in the past, which the
// host would reject as already expired.
func TestExpirationAfterNeverWraps(t *testing.T) {
	latest := uint32(math.MaxUint32 - 5)
	for ledgers := uint32(1); ledgers <= 20; ledgers++ {
		got, err := ExpirationAfter(latest, ledgers)
		if err != nil {
			continue // refused, which is the correct outcome past the ceiling
		}
		if got < latest {
			t.Fatalf("ExpirationAfter(%d, %d) returned %d, which is in the past",
				latest, ledgers, got)
		}
	}
}
