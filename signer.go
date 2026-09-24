package soroauth

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// maxAccountSignatures is the number of signatures the host accepts in a
// classic account's signature vector.
//
// The host's own constant is MAX_ACCOUNT_SIGNATURES = 20 (rs-soroban-env
// soroban-env-host/src/builtin_contracts/account_contract.rs:25), enforced at
// :185 with "too many account signers". Exceeding it fails on-chain after fees
// are paid, so it is refused here instead.
const maxAccountSignatures = 20

// Signer produces the ScVal written verbatim into a credential node's
// signature field.
//
// The shape of that ScVal is defined by the account being authorized, not by
// this library: a classic Stellar account expects a vector of
// {public_key, signature} maps, while a custom account contract's __check_auth
// may expect anything at all. That is why Sign returns an ScVal rather than raw
// signature bytes.
type Signer interface {
	// Address is the G… or C… address whose credential node this signature
	// belongs to. AuthorizeEntry writes the result only onto nodes carrying
	// this address, unless the caller overrides it with ForAddress.
	Address() string

	// Sign receives both the preimage and its 32-byte payload hash. The
	// preimage is passed so a remote or hardware signer can inspect the whole
	// structure it is approving rather than blind-signing a digest; the
	// payload is passed so a signer that only accepts a digest does not have
	// to re-derive it.
	Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)
}

// ed25519Keypair is the part of keypair.Full that signing needs. It exists so
// that the self-verification guard below can be tested: a test can supply a
// keypair whose Sign returns a signature that does not match, while Verify
// stays the genuine implementation, which is exactly the failure the guard is
// there to catch. *keypair.Full satisfies it.
type ed25519Keypair interface {
	Address() string
	Sign(input []byte) ([]byte, error)
	Verify(input, signature []byte) error
}

// scSymbol builds an ScVal symbol, the type contract map keys must use.
func scSymbol(s string) xdr.ScVal {
	symbol := xdr.ScSymbol(s)
	return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symbol}
}

// scBytes builds an ScVal byte string.
func scBytes(b []byte) xdr.ScVal {
	value := xdr.ScBytes(b)
	return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &value}
}

// scVec builds an ScVal vector.
func scVec(values ...xdr.ScVal) xdr.ScVal {
	vec := xdr.ScVec(values)
	p := &vec
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &p}
}

// accountSignature builds the single {public_key, signature} map that the host
// decodes as one AccountEd25519Signature.
//
// The host's struct is
//
//	pub(crate) struct AccountEd25519Signature {
//	    pub(crate) public_key: BytesN<32>,
//	    pub(crate) signature: BytesN<64>,
//	}
//
// (rs-soroban-env soroban-env-host/src/builtin_contracts/account_contract.rs:64).
// Keys are symbols, and the entries are written in key order — "public_key"
// before "signature" — because an ScMap is required to be sorted by key.
func accountSignature(rawPublicKey, signature []byte) xdr.ScVal {
	m := xdr.ScMap{
		{Key: scSymbol("public_key"), Val: scBytes(rawPublicKey)},
		{Key: scSymbol("signature"), Val: scBytes(signature)},
	}
	p := &m
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &p}
}

// rawEd25519Key returns the 32 raw public key bytes behind a G… address.
func rawEd25519Key(address string) ([]byte, error) {
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("%q is not an account (G…) address: %w", address, err)
	}
	return raw, nil
}

// ed25519Signer signs for a classic account with a single signing key.
type ed25519Signer struct {
	kp ed25519Keypair
}

// NewEd25519Signer returns a Signer for a classic Stellar account whose
// signing key is kp, producing the built-in account signature shape:
// a vector holding one {public_key, signature} map.
//
// The signature is verified against the payload before it is returned, and a
// mismatch is reported as ErrSignatureMismatch. One verification is cheap
// compared to what it catches — a damaged key, a faulty signer, or corrupted
// memory producing a signature that would otherwise be discovered only when
// the transaction fails on-chain, after fees are paid.
//
// A nil keypair is reported when Sign is called rather than at construction,
// because the signature of this constructor has no error to return.
func NewEd25519Signer(kp *keypair.Full) Signer {
	if kp == nil {
		// Storing a nil *keypair.Full in the interface would leave it
		// non-nil and panic on first use.
		return &ed25519Signer{}
	}
	return &ed25519Signer{kp: kp}
}

func (s *ed25519Signer) Address() string {
	if s.kp == nil {
		return ""
	}
	return s.kp.Address()
}

func (s *ed25519Signer) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", err)
	}
	if s.kp == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", ErrMissingSigner)
	}

	signature, err := s.kp.Sign(payload[:])
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", err)
	}
	if err := s.kp.Verify(payload[:], signature); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", ErrSignatureMismatch)
	}

	rawPublicKey, err := rawEd25519Key(s.kp.Address())
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", err)
	}

	return scVec(accountSignature(rawPublicKey, signature)), nil
}

// accountMultiSigner signs for a classic account with several signing keys.
type accountMultiSigner struct {
	account string
	keys    []multiSignerKey
}

type multiSignerKey struct {
	kp  ed25519Keypair
	raw []byte
}

// NewAccountMultiSigner returns a Signer for a classic Stellar account that
// requires several signatures to meet its medium threshold. account is the
// G… address being authorized, which may differ from every key's own address:
// a Stellar account's signers are not required to include its master key.
//
// The keys are sorted at construction, strictly ascending by raw 32-byte public
// key, because the host walks the vector and rejects it unless each key
// compares strictly greater than the one before it — the loop errors with
// "public keys are not ordered" otherwise (rs-soroban-env
// soroban-env-host/src/builtin_contracts/account_contract.rs:204-211). That
// same rule is why duplicate keys are rejected here: a repeat is never
// strictly ascending.
//
// Zero keys is refused as ErrMissingSigner, because the host rejects an empty
// vector outright ("no account signatures found", account_contract.rs:196).
// More than 20 keys is refused as ErrTooManySignatures (see
// maxAccountSignatures).
//
// This signer has no equivalent in the JS SDK, so it is not covered by the
// golden vectors. It is proven by unit tests and by e2e scenario C, which
// submits a transfer from a two-signer account on testnet.
func NewAccountMultiSigner(account string, kps ...*keypair.Full) (Signer, error) {
	keys := make([]ed25519Keypair, 0, len(kps))
	for i, kp := range kps {
		if kp == nil {
			return nil, fmt.Errorf("soroauth: new account multi signer: key %d is nil: %w", i, ErrMissingSigner)
		}
		keys = append(keys, kp)
	}
	return newAccountMultiSigner(account, keys...)
}

// newAccountMultiSigner carries the logic, over the testable seam.
func newAccountMultiSigner(account string, kps ...ed25519Keypair) (Signer, error) {
	if _, err := rawEd25519Key(account); err != nil {
		return nil, fmt.Errorf("soroauth: new account multi signer: %w", err)
	}
	if len(kps) == 0 {
		return nil, fmt.Errorf("soroauth: new account multi signer: %s: %w", account,
			&MissingSignerError{Address: account})
	}
	if len(kps) > maxAccountSignatures {
		return nil, fmt.Errorf("soroauth: new account multi signer: %d keys, the host accepts at most %d: %w",
			len(kps), maxAccountSignatures, ErrTooManySignatures)
	}

	keys := make([]multiSignerKey, 0, len(kps))
	for i, kp := range kps {
		if kp == nil {
			return nil, fmt.Errorf("soroauth: new account multi signer: key %d is nil: %w", i, ErrMissingSigner)
		}
		raw, err := rawEd25519Key(kp.Address())
		if err != nil {
			return nil, fmt.Errorf("soroauth: new account multi signer: %w", err)
		}
		keys = append(keys, multiSignerKey{kp: kp, raw: raw})
	}

	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].raw, keys[j].raw) < 0
	})
	for i := 1; i < len(keys); i++ {
		if bytes.Equal(keys[i-1].raw, keys[i].raw) {
			return nil, fmt.Errorf("soroauth: new account multi signer: duplicate signing key %s",
				keys[i].kp.Address())
		}
	}

	return &accountMultiSigner{account: account, keys: keys}, nil
}

func (s *accountMultiSigner) Address() string { return s.account }

func (s *accountMultiSigner) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %w", err)
	}

	signatures := make([]xdr.ScVal, 0, len(s.keys))
	for _, key := range s.keys {
		signature, err := key.kp.Sign(payload[:])
		if err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %s: %w", key.kp.Address(), err)
		}
		if err := key.kp.Verify(payload[:], signature); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %s: %w",
				key.kp.Address(), ErrSignatureMismatch)
		}
		signatures = append(signatures, accountSignature(key.raw, signature))
	}

	return scVec(signatures...), nil
}

// signerFunc adapts a plain function to the Signer interface.
type signerFunc struct {
	address string
	fn      func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)
}

// SignerFunc adapts a function to the Signer interface, for custom account
// contracts — smart wallets, and passkey or secp256r1 signers — whose
// __check_auth expects a signature shape this library does not know.
//
// The ScVal the function returns is written into the credential node verbatim,
// with no wrapping added. Nothing about it is or can be verified here: the
// caller owns both the shape and the correctness of what they return. Signers
// whose shape is known, such as NewEd25519Signer, do verify themselves.
func SignerFunc(address string, fn func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)) Signer {
	return &signerFunc{address: address, fn: fn}
}

func (s *signerFunc) Address() string { return s.address }

func (s *signerFunc) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign func: %w", err)
	}
	if s.fn == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign func: %w", ErrMissingSigner)
	}
	return s.fn(ctx, preimage, payload)
}
