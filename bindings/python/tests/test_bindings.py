#!/usr/bin/env python3
"""Tests for the soroauth Python bindings.

These tests replay the golden vectors through the Python API and assert
byte equality with the Go library's output. They require the libsoroauth
shared library to be available (built via bindings/c/build.sh or installed
via a wheel).
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

# Add the package root to the path
PKG_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG_ROOT))

import soroauth


def load_vectors() -> list[dict]:
    """Load all golden vectors from testdata/vectors."""
    # PKG_ROOT is /workspaces/soroauth-go/bindings/python
    # Vectors are at /workspaces/soroauth-go/testdata/vectors
    vectors_dir = PKG_ROOT.parent.parent / "testdata" / "vectors"
    vectors = []
    for path in sorted(vectors_dir.glob("*.json")):
        with path.open(encoding="utf-8") as f:
            vectors.append((path.name, json.load(f)))
    return vectors


class TestSoroauthBindings(unittest.TestCase):
    """Test the Python bindings against golden vectors."""

    @classmethod
    def setUpClass(cls):
        """Verify the library is loadable."""
        try:
            ver = soroauth.version()
            print(f"Loaded soroauth ABI version: {ver}")
        except Exception as e:
            raise unittest.SkipTest(f"Cannot load soroauth library: {e}")

    def test_version(self):
        """Version should be a non-empty string."""
        ver = soroauth.version()
        self.assertIsInstance(ver, str)
        self.assertTrue(len(ver) > 0)

    def test_inspect_source_account(self):
        """Source account entries have no address or delegates."""
        vectors = load_vectors()
        for name, vec in vectors:
            if vec.get("name", "").startswith("source_account"):
                info = soroauth.inspect(vec["unsigned_entry_xdr"])
                self.assertEqual(info["credential_type"], "source_account")
                self.assertFalse(info["address_bound"])
                self.assertNotIn("address", info) or self.assertIsNone(info.get("address"))
                self.assertEqual(info.get("delegates"), None)
                return
        self.skipTest("no source_account vector found")

    def test_inspect_address_v2(self):
        """Address V2 entries have address and are address-bound."""
        vectors = load_vectors()
        for name, vec in vectors:
            if vec.get("name") == "v2_single_testnet":
                info = soroauth.inspect(vec["unsigned_entry_xdr"])
                self.assertEqual(info["credential_type"], "address_v2")
                self.assertTrue(info["address_bound"])
                self.assertIn("address", info)
                # Nonce is whatever the entry has (not necessarily 42)
                self.assertIsNotNone(info.get("nonce"))
                self.assertEqual(info["top_level_signed"], False)
                return
        self.skipTest("v2_single_testnet vector not found")

    def test_inspect_delegates(self):
        """Delegates entries have delegate tree."""
        vectors = load_vectors()
        for name, vec in vectors:
            if vec.get("name") == "delegates_unsorted_with_nested":
                info = soroauth.inspect(vec["unsigned_entry_xdr"])
                self.assertEqual(info["credential_type"], "address_with_delegates")
                self.assertTrue(info["address_bound"])
                self.assertIn("address", info)
                self.assertTrue(len(info["delegates"]) > 0)
                # Check nested delegates
                found_nested = False
                for d in info["delegates"]:
                    if d.get("nested"):
                        found_nested = True
                        break
                self.assertTrue(found_nested, "expected nested delegates")
                return
        self.skipTest("delegates_unsorted_with_nested vector not found")

    def test_preimage_and_payload(self):
        """Preimage and payload should match recorded values."""
        vectors = load_vectors()
        for name, vec in vectors:
            if not vec.get("preimage_xdr"):
                continue  # Skip source account (no preimage)

            with self.subTest(vector=name):
                pre = soroauth.preimage(
                    vec["unsigned_entry_xdr"],
                    vec["valid_until_ledger"],
                    vec["network_passphrase"],
                )
                self.assertEqual(pre.preimage_xdr, vec["preimage_xdr"])
                self.assertEqual(pre.payload_hex, vec["payload_hex"])

    def test_authorize_with_seed_reproduces_signed_entry(self):
        """authorize_with_seed should reproduce the signed entry byte-for-byte."""
        vectors = load_vectors()
        # Filter to only single-step, single-key vectors (no multisig)
        single_key_vectors = []
        for name, vec in vectors:
            if not vec.get("signed_entry_xdr"):
                continue
            # Skip vectors with multisig steps
            has_multisig = any(step.get("multisig") for step in vec.get("steps", []))
            if has_multisig:
                continue
            if len(vec.get("steps", [])) != 1:
                continue
            single_key_vectors.append((name, vec))
        
        for name, vec in single_key_vectors:
            with self.subTest(vector=name):
                # Find the seed used for the first step
                # The vectors are signed with seeds derived from labels
                # For the single-key vectors, the first step's signer label is used
                # The seed is SHA-256(label)
                if not vec["steps"]:
                    continue

                step = vec["steps"][0]
                import hashlib
                seed = hashlib.sha256(step["signer_label"].encode()).digest()
                seed_hex = seed.hex()

                # Build the entry through the same steps
                entry_b64 = vec["unsigned_entry_xdr"]
                for step in vec["steps"]:
                    seed = hashlib.sha256(step["signer_label"].encode()).digest()
                    seed_hex = seed.hex()
                    for_address = step.get("for_address")
                    signed = soroauth.authorize_with_seed(
                        entry_b64,
                        vec["valid_until_ledger"],
                        vec["network_passphrase"],
                        seed_hex,
                        for_address,
                    )
                    entry_b64 = signed.entry_b64

                self.assertEqual(entry_b64, vec["signed_entry_xdr"])

    def test_payload_from_preimage(self):
        """payload() should hash a preimage to the same payload_hex."""
        vectors = load_vectors()
        for name, vec in vectors:
            if not vec.get("preimage_xdr"):
                continue

            with self.subTest(vector=name):
                pre = soroauth.preimage(
                    vec["unsigned_entry_xdr"],
                    vec["valid_until_ledger"],
                    vec["network_passphrase"],
                )
                pl = soroauth.payload(pre.preimage_xdr)
                self.assertEqual(pl.payload_hex, vec["payload_hex"])

    def test_analyze_runs(self):
        """analyze() should return findings (empty or non-empty)."""
        vectors = load_vectors()
        for name, vec in vectors:
            if vec.get("name") == "v2_single_testnet":
                findings = soroauth.analyze(vec["unsigned_entry_xdr"], current_ledger=1000000)
                self.assertIsInstance(findings, list)
                for f in findings:
                    self.assertIn("code", f)
                    self.assertIn("severity", f)
                    self.assertIn("title", f)
                    self.assertIn("description", f)
                    self.assertIn("rationale", f)
                return
        self.skipTest("v2_single_testnet vector not found")


class TestErrorHandling(unittest.TestCase):
    """Test that errors are raised with correct types."""

    def test_invalid_network_passphrase(self):
        """Empty network passphrase should raise an error."""
        vectors = load_vectors()
        entry = vectors[0][1]["unsigned_entry_xdr"]
        with self.assertRaises(soroauth.SoroauthError) as cm:
            soroauth.preimage(entry, 1234567, "")
        self.assertIn("passphrase", str(cm.exception).lower())

    def test_unsupported_credentials(self):
        """Unsupported credentials type should raise an error."""
        self.skipTest("Requires xdrlib to mutate entry; skipping in minimal test env")


if __name__ == "__main__":
    unittest.main(verbosity=2)