"""rugguard-verify — stand-alone Ed25519 signed JSON report verifier for RugGuard.

This package intentionally has a single responsibility: take a JSON report
emitted by a signed RugGuard endpoint (/v1/scan, /v1/scan/deep, /v1/explain,
/v1/pretrade/check) plus a public key, and answer one question: was the
report bit-for-bit signed by the holder of the corresponding private key?

No payment, no MCP, no SDK. ~150 lines of code, two dependencies
(cryptography + requests). An external auditor installs this with
`pip install rugguard-verify` and verifies a year-old report without
trusting RugGuard's servers at the time of verification.
"""

from rugguard_verify.verify import (
    VerificationResult,
    canonicalize,
    fetch_pubkey,
    verify_signed_report,
)

__all__ = [
    "VerificationResult",
    "canonicalize",
    "fetch_pubkey",
    "verify_signed_report",
]

__version__ = "0.1.1"
