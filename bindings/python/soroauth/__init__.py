"""
soroauth: Python bindings for the soroauth Soroban authorization signing library.

This package wraps the C ABI shared library (libsoroauth) built from the Go
source. It provides a Pythonic interface for preimage construction, signing,
inspection, and risk analysis of Soroban authorization entries.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ._ffi import ffi as _ffi
from .ffi import lib

__version__ = "0.1.0"
__all__ = [
    # Exceptions
    "SoroauthError",
    "SourceAccountCredentialsError",
    "UnsupportedCredentialsError",
    "NoMatchingCredentialNodeError",
    "DuplicateDelegateError",
    "SignatureMismatchError",
    "MissingSignerError",
    "AlreadySignedError",
    "InvalidExpirationError",
    "TooManySignaturesError",
    "DecodeLimitError",
    # Results
    "PreimageResult",
    "PayloadResult",
    "SignResult",
    # Functions
    "version",
    "preimage",
    "payload",
    "authorize_with_seed",
    "authorize_with_seeds",
    "write_signature",
    "inspect",
    "analyze",
    "render_invocations",
    "render_tree",
]

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

_KIND_MAP = {
    "SOURCE_ACCOUNT_CREDENTIALS": "SourceAccountCredentialsError",
    "UNSUPPORTED_CREDENTIALS": "UnsupportedCredentialsError",
    "NO_MATCHING_CREDENTIAL_NODE": "NoMatchingCredentialNodeError",
    "DUPLICATE_DELEGATE": "DuplicateDelegateError",
    "SIGNATURE_MISMATCH": "SignatureMismatchError",
    "MISSING_SIGNER": "MissingSignerError",
    "ALREADY_SIGNED": "AlreadySignedError",
    "INVALID_EXPIRATION": "InvalidExpirationError",
    "TOO_MANY_SIGNATURES": "TooManySignaturesError",
    "DECODE_LIMIT": "DecodeLimitError",
}


class SoroauthError(Exception):
    """Base exception for all soroauth errors."""

    def __init__(self, message: str, kind: str = "ERROR"):
        super().__init__(message)
        self.kind = kind
        self.message = message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, kind={self.kind!r})"


# Dynamically create exception subclasses
for kind, name in _KIND_MAP.items():
    globals()[name] = type(name, (SoroauthError,), {"kind": kind})

# Ensure the base ERROR kind also has a class
if "ERROR" not in _KIND_MAP.values():
    class SoroauthErrorGeneric(SoroauthError):
        kind = "ERROR"
    globals()["SoroauthErrorGeneric"] = SoroauthErrorGeneric


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class PreimageResult:
    """Result of preimage computation."""

    def __init__(self, preimage_xdr: str, payload_hex: str):
        self.preimage_xdr = preimage_xdr
        self.payload_hex = payload_hex

    def __repr__(self) -> str:
        return f"PreimageResult(preimage_xdr={self.preimage_xdr!r}, payload_hex={self.payload_hex!r})"


class PayloadResult:
    """Result of payload hashing."""

    def __init__(self, payload_hex: str):
        self.payload_hex = payload_hex

    def __repr__(self) -> str:
        return f"PayloadResult(payload_hex={self.payload_hex!r})"


class SignResult:
    """Result of signing an entry."""

    def __init__(self, entry_b64: str):
        self.entry_b64 = entry_b64

    def __repr__(self) -> str:
        return f"SignResult(entry_b64={self.entry_b64!r})"


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

def _find_library() -> Path:
    """Locate the libsoroauth shared library.

    Search order:
    1. SOROAUTH_LIB environment variable
    2. Package-relative lib/ directory (for wheel installs)
    3. Development build directory (bindings/c/dist)
    4. System library paths
    """
    # 1. Explicit override
    if env_path := os.environ.get("SOROAUTH_LIB"):
        p = Path(env_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"SOROAUTH_LIB points to non-existent path: {env_path}")

    # 2. Package-relative (wheel install)
    pkg_root = Path(__file__).resolve().parent
    lib_dir = pkg_root / "lib"
    if lib_dir.exists():
        for pattern in ("libsoroauth.so", "libsoroauth.dylib", "libsoroauth.dll"):
            matches = list(lib_dir.glob(pattern))
            if matches:
                return matches[0]

    # 3. Development build
    dev_lib = pkg_root.parent.parent.parent / "bindings" / "c" / "dist"
    if dev_lib.exists():
        for pattern in ("libsoroauth.so", "libsoroauth.dylib", "libsoroauth.dll"):
            matches = list(dev_lib.glob(pattern))
            if matches:
                return matches[0]

    # 4. System paths (ctypes will search)
    return None


# The lib object from ffi.py already has the library loaded via dlopen.
# We use it directly for all C ABI calls.


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _call(func_name: str, *args) -> Dict[str, Any]:
    """Call a C ABI function and parse the JSON envelope."""
    func = getattr(lib, func_name)
    result_ptr = func(*args)
    if result_ptr == _ffi.NULL:
        raise SoroauthError(f"{func_name}: returned NULL", kind="ERROR")

    try:
        result_json = _ffi.string(result_ptr).decode("utf-8")
    finally:
        lib.SoroauthFree(result_ptr)

    import json
    result = json.loads(result_json)

    if not result.get("ok", False):
        error_msg = result.get("error", "unknown error")
        kind = result.get("kind", "ERROR")
        exc_class = globals().get(_KIND_MAP.get(kind, "SoroauthErrorGeneric"), SoroauthError)
        raise exc_class(error_msg, kind=kind)

    return result


def _to_c_str(s: Optional[str]) -> "_ffi.CData":
    """Convert a Python string (or None) to a C string."""
    if s is None:
        return _ffi.NULL
    return _ffi.new("char[]", s.encode("utf-8"))


def _c_longlong(n: int) -> int:
    """Convert Python int to C long long (passed directly)."""
    return n


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def version() -> str:
    """Return the ABI version string."""
    ptr = lib.SoroauthVersion()
    try:
        return _ffi.string(ptr).decode("utf-8")
    finally:
        lib.SoroauthFree(ptr)


def preimage(entry_b64: str, valid_until_ledger: int, network_passphrase: str) -> PreimageResult:
    """Build the HashIdPreimage and its 32-byte payload for an entry.

    Args:
        entry_b64: base64-encoded SorobanAuthorizationEntry
        valid_until_ledger: signature expiration ledger
        network_passphrase: network passphrase (e.g., "Test SDF Network ; September 2015")

    Returns:
        PreimageResult with preimage_xdr and payload_hex
    """
    result = _call(
        "SoroauthPreimage",
        _to_c_str(entry_b64),
        _c_longlong(valid_until_ledger),
        _to_c_str(network_passphrase),
    )
    return PreimageResult(result["preimageXdr"], result["payloadHex"])


def payload(preimage_xdr_b64: str) -> PayloadResult:
    """Hash an already-constructed preimage to its 32-byte payload.

    Args:
        preimage_xdr_b64: base64-encoded HashIdPreimage

    Returns:
        PayloadResult with payload_hex
    """
    result = _call("SoroauthPayload", _to_c_str(preimage_xdr_b64))
    return PayloadResult(result["payloadHex"])


def authorize_with_seed(
    entry_b64: str,
    valid_until_ledger: int,
    network_passphrase: str,
    seed_hex: str,
    for_address: Optional[str] = None,
) -> SignResult:
    """Sign an entry with a 32-byte ed25519 seed (hex-encoded).

    Deterministic path for testing and local demos.

    Args:
        entry_b64: base64-encoded SorobanAuthorizationEntry
        valid_until_ledger: signature expiration ledger
        network_passphrase: network passphrase
        seed_hex: 32-byte ed25519 seed as hex string
        for_address: optional target address (defaults to entry's top-level address)

    Returns:
        SignResult with entry_b64
    """
    result = _call(
        "SoroauthAuthorizeWithSeed",
        _to_c_str(entry_b64),
        _c_longlong(valid_until_ledger),
        _to_c_str(network_passphrase),
        _to_c_str(seed_hex),
        _to_c_str(for_address),
    )
    return SignResult(result["entryB64"])


def authorize_with_seeds(
    entry_b64: str,
    valid_until_ledger: int,
    network_passphrase: str,
    seeds_hex: Union[str, List[str]],
    for_address: Optional[str] = None,
) -> SignResult:
    """Sign an entry with one or more 32-byte ed25519 seeds.

    Args:
        entry_b64: base64-encoded SorobanAuthorizationEntry
        valid_until_ledger: signature expiration ledger
        network_passphrase: network passphrase
        seeds_hex: single hex string, comma-separated hex string, or list of hex strings
        for_address: optional target address

    Returns:
        SignResult with entry_b64
    """
    if isinstance(seeds_hex, list):
        seeds_csv = ",".join(seeds_hex)
    else:
        seeds_csv = seeds_hex

    result = _call(
        "SoroauthAuthorizeWithSeeds",
        _to_c_str(entry_b64),
        _c_longlong(valid_until_ledger),
        _to_c_str(network_passphrase),
        _to_c_str(seeds_csv),
        _to_c_str(for_address),
    )
    return SignResult(result["entryB64"])


def write_signature(
    entry_b64: str,
    valid_until_ledger: int,
    network_passphrase: str,
    for_address: str,
    signature_scval_b64: str,
) -> SignResult:
    """Write an externally produced signature ScVal onto matching credential nodes.

    Args:
        entry_b64: base64-encoded SorobanAuthorizationEntry
        valid_until_ledger: signature expiration ledger
        network_passphrase: network passphrase
        for_address: target credential node address
        signature_scval_b64: base64-encoded ScVal signature

    Returns:
        SignResult with entry_b64
    """
    result = _call(
        "SoroauthWriteSignature",
        _to_c_str(entry_b64),
        _c_longlong(valid_until_ledger),
        _to_c_str(network_passphrase),
        _to_c_str(for_address),
        _to_c_str(signature_scval_b64),
    )
    return SignResult(result["entryB64"])


def inspect(entry_b64: str) -> Dict[str, Any]:
    """Return the entry's structure as a dictionary (EntryInfo)."""
    result = _call("SoroauthInspect", _to_c_str(entry_b64))
    import json
    return json.loads(result["infoJson"])


def analyze(
    entry_b64: str,
    current_ledger: Optional[int] = None,
    max_delegate_depth: Optional[int] = None,
    max_total_delegates: Optional[int] = None,
    max_valid_until_ledger_delta: Optional[int] = None,
    known_contracts: Optional[Dict[str, bool]] = None,
    max_sub_invocations: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Run the risk analyzer and return findings.

    Args:
        entry_b64: base64-encoded SorobanAuthorizationEntry
        current_ledger: ledger sequence for expiration checking (default: 0 = skip)
        max_delegate_depth: max delegate nesting before warning (default: 3)
        max_total_delegates: max total delegate nodes before warning (default: 10)
        max_valid_until_ledger_delta: max ledgers into future before warning (default: 10000)
        known_contracts: dict of known contract addresses (default: empty)
        max_sub_invocations: max sub-invocations before warning (default: 50)

    Returns:
        List of finding dicts with keys: code, severity, title, description, rationale
    """
    # For now, only current_ledger is exposed through the C ABI.
    # The other config options would need additional C ABI functions.
    # We pass current_ledger to the C ABI; other options use defaults.
    result = _call("SoroauthAnalyze", _to_c_str(entry_b64), _c_longlong(current_ledger or 0))
    import json
    return json.loads(result["findingsJson"])


def render_invocations(entry_b64: str) -> str:
    """Render the invocation tree as ASCII."""
    result = _call("SoroauthRenderInvocations", _to_c_str(entry_b64))
    return result["tree"]


def render_tree(entry_b64: str) -> str:
    """Render the credential/delegate tree as ASCII."""
    result = _call("SoroauthRenderTree", _to_c_str(entry_b64))
    return result["tree"]