# insumer-verify

Verifier for [InsumerAPI](https://insumermodel.com) condition-based access attestations and wallet trust profiles, in Python. ECDSA P-256 signatures, condition hashes, block freshness, expiry, and the ML-DSA-65 post-quantum companion, checked locally against the published JWKS.

This is the Python counterpart of the [`insumer-verify` npm package](https://www.npmjs.com/package/insumer-verify). Both implement the [State Attestation Specification](https://insumermodel.com/state-attestation-spec/) and both pass all 27 published [test vectors](https://insumermodel.com/.well-known/state-attestation-test-vectors.json), so a verdict from one can be reproduced with the other.

## Install

```bash
pip install insumer-verify
```

The post-quantum companion needs an ML-DSA-65 implementation, which the standard library does not have:

```bash
pip install "insumer-verify[pq]"
```

Without it the companion is reported `unverifiable`. It is never silently passed and never silently failed.

Python 3.9 or later. The only required dependency is `cryptography`.

## Get an API key

```bash
curl -X POST https://api.insumermodel.com/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","appName":"my-app","tier":"free"}'
```

## Usage

```python
import requests
from insumer_verify import verify_attestation

res = requests.post(
    "https://api.insumermodel.com/v1/attest",
    headers={"X-API-Key": KEY},
    json={
        "wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "conditions": [{
            "type": "token_balance",
            "chainId": 1,
            "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "operator": "gte",
            "threshold": "1",
        }],
    },
).json()

result = verify_attestation(res, jwks_url="https://insumermodel.com/.well-known/jwks.json", max_age=3600)

if result["valid"] and res["data"]["attestation"]["pass"]:
    grant_access()
```

Pass the **full API response**, not `res["data"]` or the attestation object. The verifier reads the signature, `kid` and companion fields beside the attestation.

`valid` is true only when every check passed. Each check reports on its own under `result["checks"]`, so a failing artifact still tells you exactly what failed:

```python
{
  "valid": False,
  "checks": {
    "signature":       {"passed": False, "reason": "Signature does not match payload"},
    "conditionHashes": {"passed": True},
    "freshness":       {"passed": True},
    "expiry":          {"passed": True},
    "pq":              {"status": "verified", "passed": True, "kid": "insumer-attest-pq1"},
  },
}
```

### JWT format

With `format: "jwt"` the API returns the attestation and two tokens beside it: `jwt` (ES256) and `pqJwt` (ML-DSA-65) over the same claims. Pass the whole response and all of it is verified and bound together; the tokens report under `checks["jwt"]`:

```python
res = requests.post(API, headers=HEADERS, json={**body, "format": "jwt"}).json()
result = verify_attestation(res, jwks_url=JWKS)
result["checks"]["jwt"]["passed"]          # the token is this attestation's, signed under the same kid
result["checks"]["jwt"]["pq"]["status"]    # "verified": pqJwt carries exactly the same claims
```

A bare token string works too. Its companion cannot travel inside it, so hand it over separately:

```python
result = verify_attestation(res["data"]["jwt"], jwks_url=JWKS, pq_jwt=res["data"]["pqJwt"])
```

### Trust profiles

```python
from insumer_verify import verify_trust_profile

res = requests.post("https://api.insumermodel.com/v1/trust", headers=HEADERS, json={"wallet": "0x..."}).json()
result = verify_trust_profile(res, jwks_url=JWKS, max_age=3600)
if result["valid"]:
    render(result["trust"])   # the verified object, exactly as parsed; render this, not your own copy
```

For `POST /v1/trust/batch`, call it once per entry of `data["results"]`.

Pass the object exactly as `json()` parsed it. Do not rebuild the `trust` object: the v1 scheme signs insertion-order JSON, so changing key order changes the signed bytes.

### Keeping records for years

Keys are never removed from the published JWKS. Save a copy beside the artifacts you retain and verification needs no network at all:

```python
result = verify_attestation(saved_response, jwks=saved_jwks)   # nothing is fetched
```

A supplied `jwks` takes precedence over `jwks_url` and is honoured exactly: a key the set does not hold fails the signature verdict with that reason, and nothing falls back to the built-in key.

## Options

All options are keyword-only.

| Option | Type | Meaning |
|---|---|---|
| `max_age` | seconds | Freshness bound on each result's `blockTimestamp` (and on a trust profile's `profiledAt` and per-check anchors). Skipped when not set |
| `clock_skew` | seconds | Allowance on the freshness and expiry comparisons. Default 60; 0 disables |
| `jwks_url` | str | Fetch the key set from this URL and select the key by `kid` |
| `jwks` | dict | A key set you already hold. Nothing is fetched; takes precedence over `jwks_url` |
| `pq_jwt` | str | The `pqJwt` companion when verifying a bare JWT string |
| `pq_required_from` | ISO string or datetime | Your own cutoff: from this date, judged by your clock, an absent or unverifiable companion fails `valid`. The only option that can make a missing companion fail. A refuted companion always fails |
| `mode` | `"access"` or `"evidence"` | `access` (default) applies the cutoff. `evidence` never refuses for a missing companion and only reports; use it when reading an artifact after the fact |
| `pq_activated_at` | ISO string or datetime | The anchored key-binding time. When set, `checks["pq"]["existedAtIssuance"]` says whether a companion could have existed when the artifact was issued. Reporting only |

With neither `jwks` nor `jwks_url`, the built-in InsumerAPI P-256 key is used for the classical signature and the companion is `unverifiable` (its key must come from a key set).

## What gets verified

| Check | What it does |
|---|---|
| **Signature** | ECDSA P-256 over the preimage the `kid` selects: v1 is bare `{id, pass, results, attestedAt}`; v2 is the domain tag plus canonical JSON with a `v: 2` member; trust v2 is the domain tag plus canonical JSON of the whole profile. A missing, unknown or wrong-artifact `kid` fails |
| **Condition hashes** | Recomputes SHA-256 of each `evaluatedCondition` (canonical JSON per the scheme) and compares to `conditionHash`. A result lacking either field fails at its index |
| **Freshness** | `blockTimestamp` age against `max_age` plus `clock_skew`. Optional |
| **Expiry** | Whether the window has elapsed, allowing `clock_skew` past `expiresAt`, with `expiresAt` bound to the signed `attestedAt`: at most 30 minutes later (5 for a delegation verdict) plus a fixed 60-second grace, so an edited future `expiresAt` cannot extend the window |
| **Post-quantum companion** | `pqSig` verified with ML-DSA-65 over the post-quantum domain tag plus the same classical preimage, key resolved by `pqKid`. In the JWT format, `pqJwt` is verified over its own `header.payload` and bound to `jwt` by the full claim set. Reported as `verified`, `refuted`, `absent` or `unverifiable` |
| **Tokens in the response** (`checks["jwt"]`) | Only when the response carries `data.jwt` beside `data.attestation`. The token is verified under the same `kid`, its condition hashes recomputed, its `jti`, `pass`, `results` and `exp` matched to the attestation, and its `pqJwt` companion reported under `checks["jwt"]["pq"]`. A failure fails `valid` |

Key selection is a verdict, not an escape. When a key set is in play and the response's `kid` selects no usable key in it, the signature check fails with that reason alone; the other checks need no key and still report their own results. Nothing is ever substituted for the key the signature claims.

A deliberately deep artifact (more than 128 nested containers) is refused as a failed check that names the refusal, never a crash and never a pass. A JSON document that deep will usually fail in `json.loads` before it reaches the verifier.

## What `valid` does not tell you

`valid` means InsumerAPI issued the artifact, it has not been modified, and it is still current. It does not mean access should be granted. Before acting on it:

1. **Check the verdict.** A validly signed attestation can say no. Read `pass`, or each `results[i]["met"]`.
2. **Pin the conditions.** Compare every `results[i]["evaluatedCondition"]` (or its `conditionHash`) with the conditions your route requires. Never trust `label`: the caller writes it.
3. **Bind the wallet.** The raw format signs no wallet for most condition types, so a raw attestation does not show whose wallet was read. Either call the API from your own server for a wallet the user has proved control of, or require `format: "jwt"` and match `sub` against that proven wallet.
4. **Reject replays by id.** Remember each attestation `id` (JWT `jti`) until it expires and refuse it a second time. Never deduplicate on the signature bytes.
5. **Treat only signed fields as evidence.** The signature covers `id`, `pass`, `results` and `attestedAt`. `passCount`, `failCount`, `expiresAt`, `ok` and `meta` are outside it.

## Preimages and hashes, exactly as implemented

The bytes InsumerAPI signs are defined by what `JSON.stringify` emits in the issuer's runtime. Python's `json` module differs from it in corners that change those bytes, so this package reproduces the JavaScript serializer rather than approximating it: ECMAScript number formatting (`1e-7`, `1e+21`, integers above 2^53 as doubles), `Object.keys` property order (array-index keys first), key sorting by UTF-16 code units rather than code points, and the array-replacer semantics of the v1 condition hash. The serializer is tested against Node.js output when `node` is on the PATH.

- **Canonical JSON (v2).** Arrays keep their order; objects emit their keys sorted as JavaScript sorts them; no whitespace; applied at every level.
- **Attestation preimage.** `insumer-attest-v1`: `JSON.stringify({id, pass, results, attestedAt})`, results exactly as received. `insumer-attest-v2`: `"insumer.attestation.v2" + "\n" + canonical({v: 2, id, pass, results, attestedAt})`.
- **Trust preimage.** `insumer-attest-v1`: `JSON.stringify(trust)` as parsed. `insumer-trust-v2`: `"insumer.trust.v2" + "\n" + canonical(trust)`, `expiresAt` included, no `v` member.
- **Condition hash.** v1: `JSON.stringify(evaluatedCondition, sorted top-level keys)`. v2: canonical JSON. Both: `"0x" + hex(SHA-256(UTF-8 bytes))`.
- **Post-quantum companion.** `pqSig`: ML-DSA-65 (FIPS 204, pure mode, empty context) over `"insumer.attestation.pq1" + "\n" + <classical preimage>`; trust profiles use `"insumer.trust.pq1"`. The key is the RFC 9964 `AKP` entry under `pqKid`. `pqJwt`: a compact JWS with `alg: "ML-DSA-65"`, bound to the ES256 token by every claim.

`classical_attest_preimage`, `classical_trust_preimage`, `condition_hash` and `canonicalize` are exported so a third party can reproduce each step without the package.

## Where this package differs from the JavaScript one

The verdicts are the same on every input the two can both read. The Python package is stricter about the caller's own options, because an option that is silently coerced or ignored is a weaker verification nobody asked for:

- `jwks` must be a dict (the parsed JWKS document); anything else is a `TypeError`, where the JavaScript treats a falsy value as unset and uses its built-in key.
- `max_age` and `clock_skew` must be numbers; a string is a `TypeError`, where the JavaScript coerces it.
- `pq_required_from` and `pq_activated_at` must be ISO 8601 strings or `datetime` objects. A value that cannot be read is a `ValueError`, where `Date.parse` would read forms like `"Jan 1 2020"` and treat an unreadable one as "no cutoff". A falsy value (`0`, `""`, `None`) is unset in both.
- Timestamps inside artifacts are read as `new Date(value)` reads them, including out-of-range fields making the value invalid, a day past the end of its month rolling over, a boolean reading as 0 or 1, and a number reading as milliseconds. Only the ISO 8601 forms are parsed; the issuer emits nothing else.

Reason strings name Python things (`pq_jwt`, `dilithium-py`) where the JavaScript names its own. The one wording difference on a verdict: an artifact nested past the depth bound is reported on the signature check as "Signature verification error: Artifact nests deeper than 128 levels", the same text the JavaScript package uses.

## Tests

```bash
pip install "insumer-verify[test]"
python -m pytest
```

The suite runs all 27 published vectors offline against a saved key set, ports the JavaScript package's offline and depth suites, cross-checks the serializer against Node.js when available, and carries a parity suite of inputs the vectors do not cover, each with the verdict the JavaScript reference gives. Set `INSUMER_VERIFY_NETWORK=1` to run the vectors against the live JWKS URL instead. The live tests in `tests/test_live.py` run only when `INSUMER_API_KEY_V2` and `INSUMER_API_KEY_V1` are set; each call spends one credit (three for a trust profile).

## Versioning

The Python package carries the version of the JavaScript release whose behaviour it matches. A Python-only fix adds a fourth component (`1.9.2.1`).

## License

MIT
