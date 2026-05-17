# rugguard-verify

Stand-alone CLI to verify Ed25519-signed JSON reports from [RugGuard](https://rugguard.redfleet.fr) — the pay-per-call pre-trade safety layer for agentic crypto trading.

## What this is

RugGuard responses on `/v1/scan`, `/v1/scan/deep`, `/v1/explain`, and `/v1/pretrade/check` carry an Ed25519 signature over the canonicalized response body. This package lets you verify that signature offline, against a public key fetched from `/v1/pubkey` (or a key file you pin yourself).

Two dependencies (`cryptography`, `requests`). No payment, no MCP, no SDK. ~200 lines of code. Designed for:

- **Agents** that need to prove to a third party what RugGuard said at the moment of trade.
- **Auditors / compliance** verifying a year-old report without trusting RugGuard's servers at the time of verification.
- **Integration kits** wrapping a verify step around every cached RugGuard response.

## Install

```bash
pip install rugguard-verify
```

## Usage

### Verify a signed report

```bash
# 1) Save a signed response (any RugGuard signed endpoint)
curl -s https://rugguard.redfleet.fr/v1/scan/base/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 > scan.json

# 2) Verify it
rugguard-verify --report scan.json
# OK
#   fingerprint: ab12cd34ef567890
#   scan_id:     9c2f3e1a-1234-4abc-8def-1234567890ab
```

### Pin a local pubkey file (no network fetch)

```bash
# Save the current pubkey once
curl -s https://rugguard.redfleet.fr/v1/pubkey | jq -r .pubkey_base64 > rugguard.pub

# Verify offline against it
rugguard-verify --report scan.json --pubkey-file rugguard.pub
```

### Read from stdin

```bash
cat scan.json | rugguard-verify --report -
```

### Verify a different deployment

```bash
rugguard-verify --report scan.json --pubkey-url https://staging.example/v1/pubkey
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Signature valid |
| `1` | Signature invalid — tampered body, fingerprint mismatch, or unsigned report |
| `2` | Usage error — bad arguments, network failure on pubkey fetch |

## Library API

For programmatic use (e.g. inside an integration kit or a custodian's audit pipeline):

```python
import json
from rugguard_verify import fetch_pubkey, verify_signed_report

with open("scan.json") as f:
    report = json.load(f)

pubkey_body = fetch_pubkey("https://rugguard.redfleet.fr/v1/pubkey")
result = verify_signed_report(report, pubkey_body["pubkey_base64"])

if result.valid:
    print(f"OK — signed by {result.pubkey_fingerprint}")
else:
    print(f"INVALID: {result.reason}")
```

## How signing works

RugGuard's signing path canonicalizes the response body deterministically:

- Keys sorted alphabetically
- No whitespace between tokens (`separators=(",", ":")`)
- `ensure_ascii=False` (unicode bytes round-trip)
- `signature` and `key_fingerprint` fields stripped before hashing

Then Ed25519-signs over those bytes. The verifier re-canonicalizes the wire body using the same rules and `Ed25519PublicKey.verify` against the signature.

Key rotation: RugGuard rotates its signing key annually (or immediately on suspicion of compromise). Historical fingerprints are published at [/trust.html](https://rugguard.redfleet.fr/trust.html) so reports signed under retired keys can still be verified.

## Limits

- **Number canonicalization** — not full RFC 8785. For the JSON shapes RugGuard emits (ints, bounded-precision floats, ISO datetimes), the Python-emitted bytes are stable. A different language re-serializing a parsed report may produce different float strings; the safe path is to verify the bytes as received.
- **Single-key model** — no cross-signing, no transparency log on-chain. The pinned pubkey from `/v1/pubkey` (or your local `--pubkey-file`) is the trust root.
- **Verifying past reports after rotation** — fetch the historical pubkey from `/trust.html` and pass via `--pubkey-file`. The fingerprint mismatch error message guides you.

## License

MIT. See [LICENSE](LICENSE).

## See also

- [RugGuard](https://rugguard.redfleet.fr) — the pre-trade safety API
- [/v1/pubkey](https://rugguard.redfleet.fr/v1/pubkey) — current signing key
- [/trust.html](https://rugguard.redfleet.fr/trust.html) — methodology, security, key rotation log
- [/openapi.json](https://rugguard.redfleet.fr/openapi.json) — full API spec
