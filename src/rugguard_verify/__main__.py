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


def _read_report(path: str) -> dict:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _resolve_pubkey(args: argparse.Namespace) -> str:
    """Return the pubkey base64 string, in this order of precedence:
    --pubkey-file > --pubkey-url > default /v1/pubkey URL."""
    if args.pubkey_file:
        return Path(args.pubkey_file).read_text(encoding="utf-8").strip()
    url = args.pubkey_url
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
        default="https://rugguard.redfleet.fr/v1/pubkey",
        help=(
            "URL to fetch the current pubkey from (default: production "
            "RugGuard /v1/pubkey)."
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
    except (OSError, json.JSONDecodeError) as exc:
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
    return _EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
