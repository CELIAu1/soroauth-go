# soroauth: Python bindings for the soroauth Soroban authorization signing library

This package provides Python access to the soroauth Go library for constructing,
signing, and inspecting Soroban authorization entries. It wraps the C ABI shared
library built from the Go source, so no Go toolchain is required at install
time—only the platform-appropriate wheel.

## Installation

```bash
pip install soroauth
```

Pre-built wheels are provided for Linux (x86_64, aarch64) and macOS (x86_64,
arm64) on Python 3.9+.

## Quick Start

```python
import soroauth

# Build a preimage and payload from an unsigned entry
entry_b64 = "..."  # base64-encoded SorobanAuthorizationEntry
preimage = soroauth.preimage(entry_b64, valid_until_ledger=1234567, network_passphrase="Test SDF Network ; September 2015")
print(f"Preimage XDR: {preimage.preimage_xdr}")
print(f"Payload hash: {preimage.payload_hex}")

# Sign an entry with an ed25519 seed (for testing/deterministic signing)
seed_hex = "00" * 32  # 32-byte seed in hex
signed = soroauth.authorize_with_seed(entry_b64, valid_until_ledger=1234567, network_passphrase="Test SDF Network ; September 2015", seed_hex=seed_hex)
print(f"Signed entry: {signed.entry_b64}")

# Inspect an entry's structure
info = soroauth.inspect(entry_b64)
print(f"Credential type: {info['credential_type']}")
print(f"Address: {info.get('address')}")
print(f"Top-level signed: {info['top_level_signed']}")

# Run risk analysis
findings = soroauth.analyze(entry_b64, current_ledger=1000000)
for f in findings:
    print(f"[{f['severity']}] {f['code']}: {f['title']} - {f['description']}")
```

## API Reference

### Exceptions

All functions raise `SoroauthError` (or a subclass) on failure. The exception
carries the error message and a `kind` attribute naming the underlying Go
sentinel error for programmatic handling.

```python
try:
    soroauth.preimage(...)
except soroauth.MissingSignerError as e:
    print(f"No signer for {e.address}")
except soroauth.SoroauthError as e:
    print(f"Error ({e.kind}): {e}")
```

Available exception types:

- `SourceAccountCredentialsError`
- `UnsupportedCredentialsError`
- `NoMatchingCredentialNodeError`
- `DuplicateDelegateError`
- `SignatureMismatchError`
- `MissingSignerError`
- `AlreadySignedError`
- `InvalidExpirationError`
- `TooManySignaturesError`
- `DecodeLimitError`
- `SoroauthError` (base class for all others)

### Preimage and Payload

#### `preimage(entry_b64, valid_until_ledger, network_passphrase) -> PreimageResult`

Builds the `HashIdPreimage` and its 32-byte SHA-256 payload for an entry.

Returns a `PreimageResult` with:

- `preimage_xdr`: base64 XDR of the `HashIdPreimage`
- `payload_hex`: hex-encoded 32-byte payload hash

#### `payload(preimage_xdr_b64) -> PayloadResult`

Hashes an already-constructed preimage to its 32-byte payload.

Returns a `PayloadResult` with:

- `payload_hex`: hex-encoded 32-byte payload hash

### Signing

#### `authorize_with_seed(entry_b64, valid_until_ledger, network_passphrase, seed_hex, for_address=None) -> SignResult`

Signs an entry using a 32-byte ed25519 seed (hex-encoded). Deterministic path
for testing and local demos.

Returns a `SignResult` with:

- `entry_b64`: base64 XDR of the signed entry

#### `authorize_with_seeds(entry_b64, valid_until_ledger, network_passphrase, seeds_hex_list, for_address=None) -> SignResult`

Signs an entry with one or more 32-byte ed25519 seeds (hex-encoded,
comma-separated string). One seed produces a single-key signature; two or more
produce an `AccountMultiSigner` signature vector (sorted by public key, max 20
keys).

#### `write_signature(entry_b64, valid_until_ledger, network_passphrase, for_address, signature_scval_b64) -> SignResult`

Writes an externally produced signature `ScVal` (base64 XDR) onto every
credential node whose address matches. Used by remote signers (passkey, hardware
wallet, etc.).

### Inspection

#### `inspect(entry_b64) -> dict`

Returns the entry's structure as a dictionary matching `EntryInfo`:

- `credential_type`: one of `source_account`, `address`, `address_v2`,
  `address_with_delegates`
- `address_bound`: bool
- `address`: top-level address (if applicable)
- `nonce`: int (if applicable)
- `valid_until_ledger`: int (if applicable)
- `top_level_signed`: bool
- `delegates`: list of node info dicts (address, signed, shape, nested)
- `root_contract`: contract address (if contract_fn)
- `root_function`: function name (if contract_fn)
- `sub_invocations`: int (total recursive count)

### Risk Analysis

#### `analyze(entry_b64, current_ledger=None, max_delegate_depth=None, max_total_delegates=None, max_valid_until_ledger_delta=None, known_contracts=None, max_sub_invocations=None) -> list[dict]`

Runs the risk analyzer and returns a list of findings, each a dict with:

- `code`: finding code (e.g., `EXPIRATION_FAR_FUTURE`, `UNSIGNED_DELEGATES`)
- `severity`: `critical`, `warning`, or `info`
- `title`: human-readable title
- `description`: detailed description
- `rationale`: why this finding matters

### Rendering

#### `render_invocations(entry_b64) -> str`

Returns the invocation tree as an ASCII string.

#### `render_tree(entry_b64) -> str`

Returns the credential/delegate tree as an ASCII string.

### Version

#### `version() -> str`

Returns the ABI version string.

## Honesty Boundaries

This binding mirrors the Go library's honesty boundaries exactly:

- **Cannot check custom accounts**: A node addressed to a `C...` contract or
  carrying a non-built-in signature shape is reported as `cannot_check`, never
  as `verified`. Only the account's own `__check_auth` defines validity.
- **Unsigned is not verified**: An unsigned node (Void or empty vector) is
  reported as `unsigned`, not `verified`. CAP-71-01 permits a Void top-level
  signature when only delegates authenticate.
- **No on-chain state**: Whether a key is actually a signer, or whether enough
  signers met the threshold, are account-state questions this library cannot see
  offline.
- **Structural only**: `inspect` and `analyze` report what an entry _says_, not
  what it _means_. They do not decode contract arguments or verify contract
  behavior.

## Building from Source

To build the wheel locally (requires Go 1.23+ and a C toolchain):

```bash
cd bindings/python
# Build the C shared library first
cd ../../..
./bindings/c/build.sh bindings/python/soroauth/lib
# Then build the wheel
cd bindings/python
pip wheel . -w dist/
```

The `bindings/c/build.sh` script produces `libsoroauth.so` (Linux) or
`libsoroauth.dylib` (macOS) plus the generated header. The Python package
includes logic to locate the shared library at runtime.

## Testing

The test suite replays every golden vector through the Python API and asserts
byte equality with the Go library's output:

```bash
pip install -e .[dev]
pytest tests/
```

The tests require the golden vectors in `../../../testdata/vectors/` relative to
the package root.

## License

MIT License - see LICENSE file for details.
