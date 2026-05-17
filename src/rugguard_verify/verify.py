"""Ed25519 signature verification for RugGuard signed JSON reports.

Canonicalization MUST match what RugGuard's signing path emits, byte-for-byte:

  - sort_keys=True
  - separators=(",", ":")
  - ensure_ascii=False
  - signature + key_fingerprint fields stripped before canonicalize

If RugGuard ever changes its canonicalization (e.g. adopts full RFC 8785
with normalized number encoding), this verifier must change in lockstep
and a major-version bump is published. The fingerprint embedded in every
signed report makes mismatched versions diagnosable.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

import requests
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


_DEFAULT_PUBKEY_URL = "https://rugguard.redfleet.fr/v1/pubkey"
_FETCH_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying one signed report.

    `valid` is the headline boolean. The other fields help an operator
    diagnose a `valid=False` result without re-running with more verbosity.
    """

    valid: bool
    reason: str
    report_fingerprint: str | None
    pubkey_fingerprint: str | None


def canonicalize(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding of a report body.

    Strips `signature` + `key_fingerprint` so the bytes the verifier
    feeds to Ed25519 match exactly what the server hashed BEFORE attaching
    those fields. The canonical form is:

      - keys sorted alphabetically
      - separators=(",", ":") so no whitespace
      - ensure_ascii=False so any unicode round-trips losslessly
      - allow_nan=False so NaN/Infinity (not valid JSON) raise rather than
        emit tokens the server's signing path explicitly rejects
    """
    base = {
        k: v
        for k, v in payload.items()
        if k not in ("signature", "key_fingerprint")
    }
    return json.dumps(
        base,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _compute_fingerprint(pubkey_bytes: bytes) -> str:
    """First 8 bytes of SHA-256(pubkey) hex-encoded — same convention as
    RugGuard's signing.py and what /v1/pubkey reports."""
    return hashlib.sha256(pubkey_bytes).hexdigest()[:16]


def _decode_pubkey(pubkey_base64: str) -> tuple[Ed25519PublicKey, bytes]:
    raw = base64.b64decode(pubkey_base64, validate=True)
    if len(raw) != 32:
        raise ValueError(
            f"expected 32-byte Ed25519 public key, got {len(raw)} bytes"
        )
    return Ed25519PublicKey.from_public_bytes(raw), raw


def fetch_pubkey(url: str = _DEFAULT_PUBKEY_URL) -> dict[str, Any]:
    """Hit /v1/pubkey and return the JSON.

    Raises:
      - requests.RequestException on network / TLS / status failure.
      - ValueError on a non-https URL, a non-'active' status, or a malformed body.

    Disables redirect following — `--pubkey-url` is a TRUST ROOT override:
    the host that answers is the cryptographic authority for every report
    verified against the returned pubkey. We never silently follow a 3xx
    to a different origin. If the configured URL redirects, treat it as
    a configuration error and fail loud.
    """
    if not url.lower().startswith("https://"):
        raise ValueError(
            f"pubkey URL must use https:// scheme (got {url!r}). The pubkey "
            "endpoint is a trust root; refusing to fetch it over plaintext."
        )
    resp = requests.get(url, timeout=_FETCH_TIMEOUT_S, allow_redirects=False)
    if resp.is_redirect or resp.is_permanent_redirect:
        raise ValueError(
            f"pubkey URL {url!r} returned a redirect (status {resp.status_code}). "
            "Refusing to follow — the redirect target would become the trust "
            "root without the user's consent. Use the final URL directly."
        )
    resp.raise_for_status()
    body = resp.json()
    status = body.get("status")
    if status != "active":
        raise ValueError(
            f"/v1/pubkey returned status={status!r}; nothing to verify against"
        )
    pubkey = body.get("pubkey_base64")
    if not isinstance(pubkey, str) or not pubkey:
        raise ValueError("/v1/pubkey response missing pubkey_base64")
    return body


def verify_signed_report(
    report: dict[str, Any],
    pubkey_base64: str,
) -> VerificationResult:
    """Verify a signed RugGuard report against a known public key.

    Returns a VerificationResult. `valid=False` carries a `reason` string
    explaining why — useful for CLI output and for log-correlation when
    a fleet of agents starts seeing failures.
    """
    report_fingerprint = report.get("key_fingerprint")
    if not isinstance(report_fingerprint, str) or not report_fingerprint:
        return VerificationResult(
            valid=False,
            reason="report has no `key_fingerprint` — likely unsigned",
            report_fingerprint=None,
            pubkey_fingerprint=None,
        )
    sig_b64 = report.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        return VerificationResult(
            valid=False,
            reason="report has no `signature` — likely unsigned",
            report_fingerprint=report_fingerprint,
            pubkey_fingerprint=None,
        )

    try:
        public_key, public_raw = _decode_pubkey(pubkey_base64)
    except (ValueError, TypeError, InvalidKey) as exc:
        return VerificationResult(
            valid=False,
            reason=f"pubkey decode failed: {exc}",
            report_fingerprint=report_fingerprint,
            pubkey_fingerprint=None,
        )
    pubkey_fingerprint = _compute_fingerprint(public_raw)

    if report_fingerprint != pubkey_fingerprint:
        # Strongly suggests the report was signed by a rotated/different key.
        # Refuse to verify rather than silently succeed against a key the
        # report didn't claim to be signed with.
        return VerificationResult(
            valid=False,
            reason=(
                f"fingerprint mismatch: report claims {report_fingerprint!r}, "
                f"provided pubkey is {pubkey_fingerprint!r}. Fetch the "
                "matching historical key from /trust.html or the rotation log."
            ),
            report_fingerprint=report_fingerprint,
            pubkey_fingerprint=pubkey_fingerprint,
        )

    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError) as exc:
        return VerificationResult(
            valid=False,
            reason=f"signature is not valid base64: {exc}",
            report_fingerprint=report_fingerprint,
            pubkey_fingerprint=pubkey_fingerprint,
        )

    canonical = canonicalize(report)
    try:
        public_key.verify(sig_bytes, canonical)
    except InvalidSignature:
        return VerificationResult(
            valid=False,
            reason=(
                "Ed25519 verify rejected the signature. The report body was "
                "tampered with after signing, or the wrong pubkey was used "
                "despite the fingerprint match (extremely unlikely)."
            ),
            report_fingerprint=report_fingerprint,
            pubkey_fingerprint=pubkey_fingerprint,
        )

    return VerificationResult(
        valid=True,
        reason="signature OK",
        report_fingerprint=report_fingerprint,
        pubkey_fingerprint=pubkey_fingerprint,
    )
