"""End-to-end tests: generate a keypair, sign a payload with the same
canonicalization RugGuard uses server-side, verify it through the public API.

These tests pin the wire-byte compatibility between the server's signing
path and this verifier's verification path. If they ever drift, signed
reports won't verify and the verifier needs a major-version bump.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rugguard_verify.verify import canonicalize, verify_signed_report


def _make_signed_report(payload: dict) -> tuple[dict, str]:
    """Generate a fresh keypair, sign `payload`, return (signed_payload, pubkey_b64).

    Mirrors src/rugguard/lib/signing.py:sign_payload exactly:
      - canonicalize (strips signature + key_fingerprint)
      - Ed25519 sign
      - attach signature + key_fingerprint to payload
    """
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub).decode("ascii")

    import hashlib

    fingerprint = hashlib.sha256(pub).hexdigest()[:16]
    sig = sk.sign(canonicalize(payload))
    signed = {
        **payload,
        "signature": base64.b64encode(sig).decode("ascii"),
        "key_fingerprint": fingerprint,
    }
    return signed, pub_b64


def test_canonicalize_is_deterministic_and_sorted() -> None:
    a = {"b": 1, "a": 2, "scanned_at": "2026-05-17T18:00:00Z"}
    b = {"a": 2, "scanned_at": "2026-05-17T18:00:00Z", "b": 1}
    assert canonicalize(a) == canonicalize(b)
    decoded = json.loads(canonicalize(a))
    assert decoded == {"a": 2, "b": 1, "scanned_at": "2026-05-17T18:00:00Z"}


def test_canonicalize_strips_signature_keys() -> None:
    body = {"foo": 1, "signature": "garbage", "key_fingerprint": "garbage"}
    out = canonicalize(body)
    assert b"signature" not in out
    assert b"key_fingerprint" not in out


def test_round_trip_valid() -> None:
    payload = {
        "scan_id": "01J9-aaaa",
        "chain": "base",
        "score": 32,
        "verdict": "low_risk",
        "scanned_at": "2026-05-17T18:00:00Z",
    }
    signed, pub_b64 = _make_signed_report(payload)
    result = verify_signed_report(signed, pub_b64)
    assert result.valid is True
    assert result.reason == "signature OK"


def test_tampered_body_rejected() -> None:
    """Flip a byte in the signed body after signing — verify must fail."""
    payload = {"x": 1, "y": 2}
    signed, pub_b64 = _make_signed_report(payload)
    signed["x"] = 99  # tamper
    result = verify_signed_report(signed, pub_b64)
    assert result.valid is False
    assert "rejected" in result.reason.lower() or "tamper" in result.reason.lower()


def test_unsigned_report_rejected() -> None:
    """A report without signature/key_fingerprint must NOT verify, even with a key."""
    payload = {"score": 50}
    _, pub_b64 = _make_signed_report({"foo": "bar"})
    result = verify_signed_report(payload, pub_b64)
    assert result.valid is False
    assert "key_fingerprint" in result.reason or "unsigned" in result.reason.lower()


def test_fingerprint_mismatch_rejected() -> None:
    """A report signed by key A but verified with key B's pubkey must fail
    BEFORE the Ed25519 verify call (cheaper, more diagnosable)."""
    payload = {"score": 50}
    signed_a, _ = _make_signed_report(payload)
    _, pub_b = _make_signed_report({"unrelated": True})
    result = verify_signed_report(signed_a, pub_b)
    assert result.valid is False
    assert "fingerprint" in result.reason.lower()


def test_invalid_pubkey_rejected() -> None:
    payload = {"score": 50}
    signed, _ = _make_signed_report(payload)
    # 16 random bytes b64 — too short to be Ed25519.
    bad_pubkey = base64.b64encode(b"\x00" * 16).decode("ascii")
    result = verify_signed_report(signed, bad_pubkey)
    assert result.valid is False
    assert "decode" in result.reason.lower() or "pubkey" in result.reason.lower()


def test_invalid_signature_base64_rejected() -> None:
    payload = {"score": 50}
    signed, pub_b64 = _make_signed_report(payload)
    signed["signature"] = "@@not-base64@@"
    result = verify_signed_report(signed, pub_b64)
    assert result.valid is False
    assert "base64" in result.reason.lower()
