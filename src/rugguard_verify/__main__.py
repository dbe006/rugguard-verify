"""CLI entrypoint for `rugguard-verify`.

Usage:

    rugguard-verify --report path/to/scan.json
    rugguard-verify --report path/to/scan.json --pubkey-file key.txt
    rugguard-verify --report path/to/scan.json --pubkey-url https://other-deployment/v1/pubkey
    cat scan.json | rugguard-verify --report -

Exit codes:
    0  signature valid
    1  signature invalid (tampering, fingerprint mismatch, unsigned report)
    2  usage error (bad arguments, network failure on pubkey fetch)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

from rugguard_verify import __version__
from rugguard_verify.verify import fetch_pubkey, verify_signed_report


_EXIT_OK = 0
_EXIT_INVALID = 1
_EXIT_USAGE = 2

# Hardcoded default trust root — the canonical RugGuard production pubkey
# endpoint. Overriding this delegates trust to whoever answers the alternate
# URL, so any non-default value triggers a stderr warning before the fetch.
_DEFAULT_PUBKEY_URL = "https://rugguard.redfleet.fr/v1/pubkey"

# Cap on the report-file size we'll parse. Real RugGuard responses are ≤ a
# few KB; a multi-MB file is either a config mistake or a DoS attempt against
# the verifier's json parser. 16 MiB matches typical HTTP-body limits.
_MAX_REPORT_BYTES = 16 * 1024 * 1024


def _read_report(path: str) -> dict:
    """Read + parse a JSON report, enforcing the size cap.

    Stdin is harder to size-bound cheaply, so for `-` we read incrementally
    and abort once we exceed the cap. File paths use `stat()` + `read_bytes()`
    so we can refuse oversize before allocating.
    """
    if path == "-":
        # Read stdin in bounded chunks; refuse if the total exceeds the cap.
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = sys.stdin.buffer.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_REPORT_BYTES:
                raise ValueError(
                    f"stdin report exceeded {_MAX_REPORT_BYTES} bytes "
                    "(refusing to parse — real RugGuard responses are KBs)"
                )
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
    p = Path(path)
    size = p.stat().st_size
    if size > _MAX_REPORT_BYTES:
        raise ValueError(
            f"report file size {size} exceeds {_MAX_REPORT_BYTES} bytes "
            "(refusing to parse — real RugGuard responses are KBs)"
        )
    return json.loads(p.read_text(encoding="utf-8"))


def _resolve_pubkey(args: argparse.Namespace) -> str:
    """Return the pubkey base64 string, in this order of precedence:
    --pubkey-file > --pubkey-url > default /v1/pubkey URL.

    Prints a stderr warning if the resolved URL is not the hardcoded
    production default — a non-default URL is a trust-root delegation
    and the user must see that explicitly to defeat social engineering
    where someone runs `rugguard-verify --pubkey-url https://attacker/...`
    against a report the attacker pre-signed."""
    if args.pubkey_file:
        return Path(args.pubkey_file).read_text(encoding="utf-8").strip()
    url = args.pubkey_url
    if url != _DEFAULT_PUBKEY_URL:
        print(
            f"warning: trust root is {url} (non-default). The host that "
            "answers becomes the cryptographic authority for this verification.",
            file=sys.stderr,
        )
    pubkey_body = fetch_pubkey(url)
    pubkey = pubkey_body.get("pubkey_base64")
    if not isinstance(pubkey, str):
        raise ValueError(f"/v1/pubkey at {url} returned no pubkey_base64")
    return pubkey


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="rugguard-verify",
        description=(
            "Verify an Ed25519-signed JSON report from RugGuard. "
            "Returns exit 0 if valid, 1 if invalid, 2 on usage error."
        ),
    )
    parser.add_argument(
        "--report",
        required=True,
        help=(
            "Path to a JSON file containing a signed RugGuard response. "
            "Use '-' to read from stdin."
        ),
    )
    parser.add_argument(
        "--pubkey-url",
        default=_DEFAULT_PUBKEY_URL,
        help=(
            "URL to fetch the current pubkey from (default: production "
            "RugGuard /v1/pubkey). Overriding this delegates the trust "
            "root to a different server — a stderr warning is printed."
        ),
    )
    parser.add_argument(
        "--pubkey-file",
        default=None,
        help=(
            "Local file containing the base64 pubkey to verify against "
            "(skips the HTTP fetch). Useful for archived reports signed "
            "with rotated keys — fetch the historical key from /trust.html."
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success output; only print on invalid.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"rugguard-verify {__version__}",
    )
    args = parser.parse_args()

    try:
        report = _read_report(args.report)
    except (OSError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        # ValueError covers our own size-cap; RecursionError covers
        # deeply-nested adversarial JSON that blows the Python recursion
        # limit before json itself raises.
        print(f"error: could not read report: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    if not isinstance(report, dict):
        print(
            "error: report is not a JSON object (signed reports are top-level dicts)",
            file=sys.stderr,
        )
        return _EXIT_USAGE

    try:
        pubkey = _resolve_pubkey(args)
    except requests.RequestException as exc:
        print(f"error: could not fetch /v1/pubkey: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    except (OSError, ValueError) as exc:
        print(f"error: could not load pubkey: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    result = verify_signed_report(report, pubkey)

    if result.valid:
        if not args.quiet:
            print("OK")
            print(f"  fingerprint: {result.pubkey_fingerprint}")
            if "scan_id" in report:
                print(f"  scan_id:     {report['scan_id']}")
        return _EXIT_OK

    print("INVALID", file=sys.stderr)
    print(f"  reason: {result.reason}", file=sys.stderr)
    if result.report_fingerprint:
        print(f"  report claims key: {result.report_fingerprint}", file=sys.stderr)
    if result.pubkey_fingerprint:
        print(f"  provided key:      {result.pubkey_fingerprint}", file=sys.stderr)
    # If the failure is a fingerprint mismatch, the report was almost
    # certainly signed by a now-rotated key. Point the user at the
    # historical-key archive so they don't have to figure that out.
    if (
        result.report_fingerprint
        and result.pubkey_fingerprint
        and result.report_fingerprint != result.pubkey_fingerprint
    ):
        print(
            "  hint: this report appears to be signed by a rotated key. "
            "Fetch the matching historical pubkey from "
            "https://rugguard.redfleet.fr/trust.html and re-run with "
            "--pubkey-file <path-to-archived-key>.",
            file=sys.stderr,
        )
    return _EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
