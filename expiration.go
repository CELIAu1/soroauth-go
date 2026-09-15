package soroauth

import (
	"fmt"
	"math"
)

// ExpirationAfter returns the expiration ledger that is ledgers ahead of
// latestLedger, for callers turning "valid for about an hour" into the absolute
// ledger number an entry must carry.
//
// The semantics of that number, both read from the host rather than inferred:
//
// It is inclusive. The host rejects only once the current ledger is past the
// stored value — verify_and_consume_nonce fails with "signature has expired"
// when `ledger_seq > *live_until_ledger` (rs-soroban-env
// soroban-env-host/src/auth.rs). So the expiration ledger itself is still
// valid, and a value of latestLedger+1 is good for one more ledger. The JS SDK
// doc comment describes the bound as exclusive; the host source is the
// authority.
//
// It has an upper bound this function cannot enforce. The host also rejects a
// value above the network's max_live_until_ledger, with "signature expiration
// is too late" (same function). That is a network setting, so it cannot be
// known offline and is deliberately not hard-coded here: a constant baked into
// this library would silently become wrong when the network changed it. Callers
// who need the real ceiling must read it from the network.
//
// ledgers must be at least 1. Zero would produce an expiration equal to
// latestLedger, which is valid for the current ledger only and almost certainly
// not what the caller meant, so it is refused with ErrInvalidExpiration rather
// than quietly producing a signature that expires immediately. An overflowing
// sum is refused for the same reason: wrapping would turn a long lifetime into
// an expiration in the past.
func ExpirationAfter(latestLedger, ledgers uint32) (uint32, error) {
	if ledgers == 0 {
		return 0, fmt.Errorf(
			"soroauth: expiration after: ledgers must be at least 1: %w", ErrInvalidExpiration)
	}
	if latestLedger > math.MaxUint32-ledgers {
		return 0, fmt.Errorf(
			"soroauth: expiration after: %d + %d overflows a ledger sequence: %w",
			latestLedger, ledgers, ErrInvalidExpiration)
	}
	return latestLedger + ledgers, nil
}
