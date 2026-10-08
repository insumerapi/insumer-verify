# insumer-verify

Client-side verifier for [InsumerAPI](https://insumermodel.com/developers/) wallet auth attestations. Validates ECDSA P-256 signatures, condition hashes, block freshness, and attestation expiry. Zero runtime dependencies. Web Crypto API. Node.js 18+ and modern browsers. Type-agnostic: verifies every condition type (`token_balance`, `nft_ownership`, `eas_attestation`, `farcaster_id`, `evm_view_call`, `ratio_to_amount`, `ratio_to_supply`, `erc8004_agent`, `erc7710_delegation`, `account_code`) by recomputing the condition hash from the signed `evaluatedCondition`; the only type-specific rule is the 5-minute issuance window applied when a result carries `erc7710_delegation`.

Part of the InsumerAPI ecosystem: [REST API](https://insumermodel.com/developers/) (46 endpoints, 37 chains) | [MCP server](https://www.npmjs.com/package/mcp-server-insumer) (npm) | [LangChain](https://pypi.org/project/langchain-insumer/) (PyPI) | [ElizaOS](https://www.npmjs.com/package/@insumermodel/plugin-eliza) (10 actions, npm) | [OpenAI GPT](https://chatgpt.com/g/g-699c5e43ce2481918b3f1e7f144c8a49-insumerapi-verify) (GPT Store)

## Install

```bash
npm install insumer-verify
```

The same verifier is on PyPI for Python 3.9+, built from [`python/`](./python/) in this repository: `pip install insumer-verify` (add `[pq]` to check the post-quantum signature). Both packages implement the same specification and pass the same 27 published test vectors; see [python/README.md](./python/README.md).

## Get an API Key

Generate one from your terminal — no browser needed:

```bash
curl -s -X POST https://api.insumermodel.com/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "appName": "insumer-verify", "tier": "free"}' | jq .
```

Returns an `insr_live_...` key with 10 free verifications plus 100 requests a day. One free key per email.

Or get one at [insumermodel.com/developers](https://insumermodel.com/developers/).

## Usage

Call InsumerAPI, get a signed attestation, verify it:

```typescript
import { verifyAttestation } from "insumer-verify";

// 1. Call InsumerAPI
const res = await fetch("https://api.insumermodel.com/v1/attest", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "insr_live_your_key_here",
  },
  body: JSON.stringify({
    wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    conditions: [
      {
        type: "token_balance",
        chainId: 1,
        contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        threshold: "1000", // decimal string — new keys are v2 and reject a JSON number with 400
        label: "USDC >= 1000 on Ethereum",
      },
    ],
  }),
});

const apiResponse = await res.json();

// 2. Verify the attestation (signature, condition hashes, freshness, expiry)
const result = await verifyAttestation(apiResponse, {
  jwksUrl: "https://insumermodel.com/.well-known/jwks.json",
  maxAge: 120,
});

if (result.valid) {
  const { pass, results } = apiResponse.data.attestation;
  console.log(`All conditions ${pass ? "met" : "not met"}`);
  for (const r of results) {
    console.log(`  ${r.label}: ${r.met ? "met" : "not met"}`);
  }
} else {
  console.log("Verification failed:", result.checks);
}
```

### What the API returns

The sample below is a real v2-scheme response, kept byte-exact so you can verify its signature, its post-quantum signature, and its condition hash yourself (it is past its 30-minute expiry, so expect `expiry: false` and every other verdict to pass). Keys minted before the v2 rollout return the same envelope under `kid: insumer-attest-v1`.

```json
{
  "ok": true,
  "data": {
    "attestation": {
      "id": "ATST-3E001BD9A949B622",
      "pass": true,
      "results": [
        {
          "condition": 0,
          "label": "ETH >= 1",
          "type": "token_balance",
          "chainId": 1,
          "met": true,
          "evaluatedCondition": {
            "type": "token_balance",
            "chainId": 1,
            "contractAddress": "native",
            "operator": "gte",
            "threshold": "1"
          },
          "conditionHash": "0xedb298fabbe0e15fe630067090b93b11fc8fd110ecd1cdbdebd1cceb9257c907",
          "blockNumber": "0x18b11d2",
          "blockTimestamp": "2026-09-02T18:04:23.000Z"
        }
      ],
      "passCount": 1,
      "failCount": 0,
      "attestedAt": "2026-09-02T18:04:35.370Z",
      "expiresAt": "2026-09-02T18:34:35.370Z"
    },
    "sig": "+9a4O7E7C4d23BQiAJerxPTN3TTB+7iCI79VEbqdUHQ8SkB0aRRMQlEqkuAgeF4wTzo5dhKhk0Rhog7N6XJC9A==",
    "kid": "insumer-attest-v2",
    "pqSig": "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",
    "pqKid": "insumer-attest-pq1"
  },
  "meta": {
    "version": "1.0",
    "timestamp": "2026-09-02T18:04:35.485Z",
    "creditsRemaining": 998,
    "creditsCharged": 1
  }
}
```

No balances. No amounts. Just a signed true/false per condition.

#### XRPL-specific fields

XRPL attestation results use `ledgerIndex` (integer) and `ledgerHash` (string) instead of `blockNumber` and `blockTimestamp`:

```json
{
  "condition": 0,
  "met": true,
  "label": "RLUSD >= 100 on XRPL",
  "type": "token_balance",
  "chainId": "xrpl",
  "evaluatedCondition": {
    "type": "token_balance",
    "chainId": "xrpl",
    "contractAddress": "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De",
    "currency": "524C555344000000000000000000000000000000",
    "operator": "gte",
    "threshold": "100"
  },
  "conditionHash": "0x9f2c...",
  "ledgerIndex": 96482715,
  "ledgerHash": "A1B2C3D4..."
}
```

Trust line token conditions may also include `trustLineState` with a `frozen` boolean indicating whether the trust line is frozen:

```json
"trustLineState": { "frozen": false }
```

Because XRPL results have no `blockTimestamp`, the freshness check (`maxAge`) skips them rather than failing. Condition hash and signature checks work identically across all chains.

### Handling `rpc_failure` errors

If the API cannot reach one or more upstream data sources after retries, it returns `ok: false` with error code `rpc_failure` instead of issuing an attestation. **No signature, no JWT, no credits charged.** This is a retryable error — retry the same request after a short delay (2-5 seconds).

```json
{
  "ok": false,
  "error": {
    "code": "rpc_failure",
    "message": "Unable to verify all conditions — data source unavailable after retries",
    "failedConditions": [
      { "source": "balance_read", "chainId": 43114, "message": "..." }
    ]
  },
  "meta": { "version": "1.0", "timestamp": "..." }
}
```

**Important:** `rpc_failure` is NOT a verification failure. It means the API could not check the condition at all. Do not treat it as `pass: false`. Check for `ok: false` with `error.code === "rpc_failure"` and retry:

```typescript
const res = await fetch("https://api.insumermodel.com/v1/attest", { ... });
const data = await res.json();

if (!data.ok && data.error?.code === "rpc_failure") {
  // Retryable — data source temporarily unavailable
  // Wait 2-5 seconds and retry the same request
  console.log("RPC failure, retrying...", data.error.failedConditions);
  return;
}

// Only verify if we got an actual attestation
const result = await verifyAttestation(data, { maxAge: 120 });
```

### Browser

```html
<script type="module">
  import { verifyAttestation } from "https://esm.sh/insumer-verify@1.9.3";

  // apiResponse = attestation from your backend
  const result = await verifyAttestation(apiResponse, {
    jwksUrl: "https://insumermodel.com/.well-known/jwks.json",
  });
  console.log(result.valid, result.checks);
</script>
```

### Freshness check

Pass `maxAge` (seconds) to reject attestations where block data is too old:

```typescript
const result = await verifyAttestation(apiResponse, { maxAge: 120 });
// Fails if any blockTimestamp is older than 120 seconds (plus the clock-skew allowance below)
```

Every EVM result carries a `blockTimestamp`. Results on Solana, XRPL, Bitcoin, Tron, Stellar and Sui carry none (each has its own anchor: `slot`, `ledgerIndex`, `blockHeight`, or `checkpointSequence`), so the freshness check skips them rather than treating them as failures. XRPL results use `ledgerIndex` and `ledgerHash` instead.

### Clock tolerances

Two tolerances apply to the clock-based checks. Both are verifier-side allowances the spec permits; neither changes what the API issues or what is signed.

**Clock skew (`clockSkew`, default 60 seconds).** The spec's freshness section (9.4) recommends that a verifier allow about 60 seconds of clock skew and block propagation delay. The library applies that allowance to every comparison against its own clock: a `blockTimestamp` (or a trust profile's `profiledAt` and per-check `blockTimestamp`) may be up to `clockSkew` seconds older than `maxAge` allows, and an `expiresAt` (or JWT `exp`) up to `clockSkew` seconds in the past is still current. Set `clockSkew: 0` for strict comparison, or raise it for hosts with a known drift:

```typescript
await verifyAttestation(apiResponse, { maxAge: 120, clockSkew: 0 });   // strict
await verifyAttestation(apiResponse, { maxAge: 120, clockSkew: 120 }); // two minutes of skew
```

`clockSkew` does not move your own `pqRequiredFrom` cutoff and does not apply to the binding below.

**Binding grace (`EXPIRY_BINDING_GRACE_MS`, fixed at 60 seconds).** Check 4 binds the unsigned `expiresAt` to the signed `attestedAt`: an `expiresAt` further from `attestedAt` than the issuance window (30 minutes, or 5 with a delegation condition) is rejected as tampered. The library allows 60 seconds beyond the window for rounding at the boundary. That grace is a verifier tolerance the spec permits (up to 60 seconds); it is a named, exported constant rather than an option, so it cannot be widened per call. Both constants are exported (`DEFAULT_CLOCK_SKEW_SECONDS`, `EXPIRY_BINDING_GRACE_MS`) so an integration can state the values it runs under.

**Canonicalization depth (`MAX_CANONICAL_DEPTH`, fixed at 128 levels).** Canonicalization runs alongside signature verification rather than after it, so the walk is reachable by anyone holding an artifact, valid signature or not. The library enforces an explicit bound of 128 nested containers and refuses anything deeper with a stated reason, reported as a failed check like any other. 128 matches the bound proposed in A2A PR #2246 and in-toto/attestation PR #570, so a verifier that refuses here refuses what those refuse. For scale, the deepest artifact in the published conformance corpus nests 9 levels. Like the constants above it is exported and fixed rather than a per-call option.

### JWKS key discovery

On the raw attestation and trust paths, insumer-verify uses the hardcoded InsumerAPI ECDSA public key unless you pass `jwksUrl` or `jwks`; the JWT path and the post-quantum signature always resolve their keys from a JWKS (fetched from `jwksUrl`, default `https://insumermodel.com/.well-known/jwks.json`, or the `jwks` object you supply). Unless `jwks` is supplied, the JWT path fetches the JWKS on each call; for a high-volume gate, pass a cached key set as `jwks`. If the key set may be unreachable when you verify (an offline gate, a record read years later), supply a saved copy as `jwks`: nothing is fetched on any path, and every verdict comes from the same key set. With neither option set, an outage reaches the two input formats differently, because only the raw paths carry a built-in key: a raw response still verifies classically and reports its post-quantum signature `unverifiable` (the post-quantum key comes only from a key set), while a JWT string fails the signature verdict with the fetch error. Opt in to dynamic key discovery for the raw paths too:

```typescript
const result = await verifyAttestation(apiResponse, {
  jwksUrl: "https://insumermodel.com/.well-known/jwks.json",
});
```

When `jwksUrl` is set, the library fetches the JWKS, matches the key by `kid` from the attestation response, and uses it for signature verification. This enables automatic key rotation without library updates. A `kid` that matches no key in the document is a verification failure, and so is a response with no `kid` at all: the library never falls back to another key or to a position in the set, because the set holds keys of two types and the first key in a JWKS is not the key the signature claims. A `kid` is also bound to its artifact type: attestations verify only under `insumer-attest-v1` or `insumer-attest-v2`, trust profiles only under `insumer-attest-v1` or `insumer-trust-v2`, and a post-quantum signature only under the `pqKid` for that artifact (`insumer-attest-pq1` or `insumer-trust-pq1`).

When the `kid` selects no key, that is the signature verdict's failure alone. Condition hashes, freshness and expiry need no key and are still computed and reported on their own, and the post-quantum signature is reported as `absent` when none was transmitted or `unverifiable` when one was (a `kid` that selects no key selects no preimage to rebuild it over). `valid` is false either way; nothing is ever checked against a key the response did not name.

**Trust contract.** `jwksUrl` should be a hardcoded constant (e.g. the InsumerAPI JWKS endpoint) or another URL you control — set once at integration time. The library fetches whatever URL you pass, so passing untrusted user input would let a caller direct the library to fetch arbitrary endpoints on the host's behalf.

### Keeping records for years (offline verification)

If you keep attestations or trust profiles as records, keep a copy of the JWKS with them and verify against that copy with the `jwks` option. Nothing is fetched, so a record stays checkable whether or not the issuer's endpoints are reachable, and both the ECDSA signature and the ML-DSA-65 post-quantum signature are covered. InsumerAPI never removes keys from its JWKS (spec Section 4.2), so a copy saved today remains valid for everything signed before you saved it. This package ships a snapshot in `keys/jwks.json`, together with `keys/pq-key-binding.json`, the key-binding document whose digest is anchored on Base.

```typescript
import { readFileSync } from "node:fs";
const savedJwks = JSON.parse(readFileSync("./records/insumer-jwks.json", "utf8"));

// Reading an old record: evidence mode reports every verdict and never refuses for a missing post-quantum signature.
const result = await verifyAttestation(storedResponse, { jwks: savedJwks, mode: "evidence" });
```

**Trust contract.** Treat a supplied key set the way you treat `jwksUrl`: use only a copy you saved from InsumerAPI's own endpoints. The library believes whatever keys you hand it, so a key set from anyone else could make their signatures verify. If you are unsure where a copy came from, compare it with `keys/pq-key-binding.json` in this package, whose digest is anchored on Base.

A supplied `jwks` takes precedence over `jwksUrl` and is used exactly as given: a key missing from it is not fetched from anywhere else (a missing post-quantum key makes `checks.pq` unverifiable, not refuted). An expired attestation still fails `checks.expiry`; keeping the key keeps the signature checkable, it does not make an old attestation valid for access.

### Signing scheme versions (v1 / v2)

InsumerAPI signs attestations with one of two schemes; the `kid` on each response selects which, and this library verifies **both automatically** — you don't need to do anything:

- **`insumer-attest-v1`** — signature over the bare `JSON.stringify({id, pass, results, attestedAt})`. Frozen.
- **`insumer-attest-v2`** — signature over a domain-separated, canonical preimage: `"insumer.attestation.v2\n"` + recursive-sorted-key canonical JSON of `{v:2, id, pass, results, attestedAt}`. Condition hashes use the same recursive canonicalization. In a v2 `evaluatedCondition`, `threshold` is a canonical decimal **string** and there is no `decimals` field.

All newly issued API keys are v2. The JWKS publishes five entries over two keys: three `kid`s over the same ECDSA key (`insumer-attest-v1`, `insumer-attest-v2`, `insumer-trust-v2`), followed by two RFC 9964 `AKP` entries for the ML-DSA-65 post-quantum key (`insumer-attest-pq1`, `insumer-trust-pq1`); resolve every key by `kid`, never by position. This library verifies both attestations (`verifyAttestation`) and trust profiles (`verifyTrustProfile`, below), selecting the scheme from the `kid` on each response.

> When you create a v2 key, send `/v1/attest` `threshold` values as decimal **strings** (`"100"`), not numbers — a JSON number is rejected with 400. This is a request-side requirement; it does not affect verification.

## Post-quantum signature (fifth verdict)

Responses from the API are signed twice: ES256 and a post-quantum ML-DSA-65 signature. The
post-quantum signature is `pqSig` + `pqKid` on the raw format, and a sibling `pqJwt` (a compact JWS,
`alg: "ML-DSA-65"`, RFC 9964) on the JWT format. Nothing about `sig`, `kid`, or `jwt` changes.
The post-quantum signature covers the same bytes the classical `kid` selects, under its own domain tag
(`insumer.attestation.pq1`), and its public key is an RFC 9964 JWK (`kty: "AKP"`) in the same
JWKS, resolved by `pqKid`.

Trust profiles carry the same post-quantum signature under `pqKid: insumer-trust-pq1` (domain `insumer.trust.pq1`), and `verifyTrustProfile` reports it the same way. The verifier reports it as an independent verdict, `checks.pq`:

| `pq.status`    | meaning                                                                      |
|----------------|------------------------------------------------------------------------------|
| `verified`     | post-quantum signature present, key resolved by `pqKid`, signature verifies               |
| `refuted`      | post-quantum signature present and FAILS (tampered, wrong key, a `pqJwt` whose claims differ from the `jwt`'s, or a `pqJwt` whose header lacks the algorithm or a kid: the header is covered by the post-quantum signature itself and the issuer always emits both) |
| `absent`       | no post-quantum signature on this response (normal for artifacts issued before PQ signing)|
| `unverifiable` | present but could not be checked: unknown `pqKid`, `pqSig` sent without `pqKid` (an unsigned sibling, so its absence is a gap rather than evidence), a post-quantum kid for the other artifact type, JWKS unreachable, or no ML-DSA implementation in this runtime |

A classical `kid` this library does not know selects no preimage, so the post-quantum signature is `unverifiable`, never `refuted`: a verifier must tolerate a signing kid it has not met. A known kid naming the wrong artifact type is a relabelled artifact and stays `refuted`.

`refuted` always fails `valid`. `absent` and `unverifiable` are reported and do not affect
`valid` unless you set your own cutoff:

```js
// Live access decision: from this date, require a verified post-quantum signature.
await verifyAttestation(response, { jwksUrl, pqRequiredFrom: "2027-06-01T00:00:00Z" });

// Reading an artifact after the fact (audit, dispute): never refused for lacking a post-quantum signature;
// pqActivatedAt (the anchored binding date) lets the verifier say whether one existed at issuance.
const r = await verifyAttestation(response, { jwksUrl, mode: "evidence", pqActivatedAt: bindingDate });
r.checks.pq.status;            // "absent"
r.checks.pq.existedAtIssuance; // false -> the post-quantum signature did not exist when this was issued
```

ML-DSA is not in Web Crypto. Install the optional peer dependency to verify post-quantum signatures:

```
npm install @noble/post-quantum
```

`@noble/post-quantum` requires Node.js 20.19 or later, so checking the post-quantum signature needs that version; everything else runs on Node.js 18+.

Without it the post-quantum signature is reported as `unverifiable` with a reason, never silently passed or failed.
When you verify a **bare JWT string**, the post-quantum signature cannot travel with it: pass it as
`options.pqJwt`, or wrap the pair as `{ data: { jwt, pqJwt } }`. Omit it and the verdict is
`absent` (which a `pqRequiredFrom` policy refuses) on an artifact whose post-quantum signature would
verify. Note that `{ data: { jwt, pqJwt } }` is a tokens-only wrapper, not the `format: "jwt"
response`, which also carries `attestation`, `sig` and `kid`; hand that whole response over as
it came and the post-quantum signature is picked up from `data.pqJwt` for you.

## API

### `verifyAttestation(response, options?)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `response` | `unknown` | Full InsumerAPI response envelope (must contain `data.attestation` and `data.sig`) |
| `options.maxAge` | `number` | Optional max age in seconds for block freshness check |
| `options.clockSkew` | `number` | Clock-skew allowance in seconds for the freshness and expiry checks (default `60`; `0` disables). See "Clock tolerances" |
| `options.jwksUrl` | `string` | Optional JWKS URL for dynamic key discovery (e.g. `https://insumermodel.com/.well-known/jwks.json`) |
| `options.jwks` | `{ keys: JwksKey[] }` | A key set you already hold (e.g. a saved copy kept with your records). Resolves both the ECDSA and ML-DSA-65 keys from it; nothing is fetched; takes precedence over `jwksUrl`. See "Keeping records for years" |
| `options.pqJwt` | `string` | The `pqJwt` sibling, when verifying a JWT string; the object envelope form picks it up from `data.pqJwt` automatically |
| `options.pqRequiredFrom` | `string \| Date` | Your own cutoff: an absent or unverifiable post-quantum signature fails only once this date has passed, judged by your clock. **This is the only option that can make an absent or unverifiable post-quantum signature fail `valid`.** A refuted post-quantum signature always fails |
| `options.mode` | `"access" \| "evidence"` | `access` (default) applies the cutoff; `evidence` never refuses for a missing post-quantum signature and only reports |
| `options.pqActivatedAt` | `string \| Date` | The anchored key-binding block time; when set, `checks.pq.existedAtIssuance` says whether a post-quantum signature could have existed when the artifact was issued. **Reporting only: it never affects `passed` or `valid`.** To enforce the post-quantum signature, set `pqRequiredFrom` |

> **Common mistake:** Pass the **full API response** (`await res.json()`), not `response.data` or `response.data.attestation`. The function expects the outer envelope `{ok, data: {attestation, sig, kid}, meta}`. Passing the inner `data` object will throw `"Invalid response: missing data object"`.

Returns `Promise<VerifyResult>`:

```typescript
interface VerifyResult {
  valid: boolean; // true only if ALL checks pass
  checks: {
    signature: { passed: boolean; reason?: string };
    conditionHashes: { passed: boolean; failures?: number[]; reason?: string };
    freshness: { passed: boolean; reason?: string };
    expiry: { passed: boolean; reason?: string };
    pq: {
      status: "verified" | "refuted" | "absent" | "unverifiable";
      passed: boolean;            // policy outcome under your options
      kid?: string;               // the pqKid that was checked
      existedAtIssuance?: boolean; // only with options.pqActivatedAt
      reason?: string;
    };
    jwt?: {                       // only when the response object carries data.jwt
      passed: boolean;
      reason?: string;
      pq?: { status: "verified" | "refuted" | "absent" | "unverifiable"; passed: boolean; kid?: string; reason?: string };
    };
  };
}
```

### `verifyTrustProfile(response, options?)`

Verifies a wallet trust profile from `POST /v1/trust` (or a single entry of `POST /v1/trust/batch`).

| Parameter | Type | Description |
|-----------|------|-------------|
| `response` | `unknown` | The `POST /v1/trust` response envelope `{ok, data: {trust, sig, kid}, meta}`, or a bare `{trust, sig, kid}` entry from a batch response |
| `options.maxAge` | `number` | Optional max age in seconds — applied to both `profiledAt` and each dimension's on-chain `blockTimestamp` |
| `options.clockSkew` | `number` | Clock-skew allowance in seconds for the freshness and expiry checks (default `60`; `0` disables) |
| `options.jwksUrl` | `string` | Optional JWKS URL for dynamic key discovery |
| `options.jwks` | `{ keys: JwksKey[] }` | A saved key set; same meaning as on `verifyAttestation` |
| `options.pqRequiredFrom`, `options.mode`, `options.pqActivatedAt` | | Same meaning as on `verifyAttestation`; the post-quantum signature on a trust profile carries `pqKid: insumer-trust-pq1` |

The scheme is selected by `kid`: `insumer-trust-v2` (domain-separated canonical preimage) or `insumer-attest-v1` (legacy bare-JSON). Pass the `trust` object exactly as received — do **not** rebuild it, since the v1 scheme signs `JSON.stringify` output in insertion order. For `POST /v1/trust/batch`, call once per `data.results[i]` entry.

**Checks that were not evaluated (spec 11.3).** A curated check on a chain whose wallet was not supplied in the request (Solana, XRPL, Stellar, Sui) stays in the signed profile with `evaluated: false`, `reason: "wallet_not_provided"`, and `requires` naming the parameter; it carries no chain anchor, its `met` is `false`, and it is counted in the dimension's `notEvaluatedCount` and the summary's `totalNotEvaluated` rather than in pass or fail. The verifier does not reinterpret these checks: they are signed content, so the classical and post-quantum signature checks cover them exactly as issued; the freshness check skips them because they carry no `blockTimestamp`; and the profile's own counts are authoritative. Do not read an unevaluated check as evidence that its condition was not met.

Returns `Promise<TrustVerifyResult>`:

```typescript
interface TrustVerifyResult {
  valid: boolean;       // true only if ALL checks pass
  trust?: TrustProfile; // the verified profile — render THIS (gated on valid), not your own copy
  checks: {
    signature: { passed: boolean; reason?: string };
    freshness: { passed: boolean; reason?: string };
    expiry: { passed: boolean; reason?: string };
    pq: { status: "verified" | "refuted" | "absent" | "unverifiable"; passed: boolean; kid?: string; reason?: string };
  };
}
```

```javascript
import { verifyTrustProfile } from "insumer-verify";

const res = await fetch("https://api.insumermodel.com/v1/trust", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-API-Key": KEY },
  body: JSON.stringify({ wallet: "0x…" }),
});
const result = await verifyTrustProfile(await res.json(), {
  jwksUrl: "https://insumermodel.com/.well-known/jwks.json",
});
if (result.valid) render(result.trust);
```

## What gets verified

| Check | What it does |
|-------|-------------|
| **Signature** | Verifies the ECDSA P-256 signature over the preimage the `kid` selects (v1: bare `{id, pass, results, attestedAt}`; v2: the domain tag plus canonical JSON with a `v:2` member; trust v2: the domain tag plus canonical JSON of the whole trust object) using the key the `kid` names. A missing, unknown, or wrong-artifact `kid` fails |
| **Condition hashes** | Recomputes SHA-256 of each `evaluatedCondition` (canonical JSON per the scheme the `kid` selects; a `kid` that selects no scheme is recomputed under the v1 form, which agrees with v2 on every flat condition the API issues) and compares to `conditionHash`; a result lacking either field fails |
| **Freshness** | Checks `blockTimestamp` age against caller-defined `maxAge` plus the `clockSkew` allowance (optional, skipped if `maxAge` is not set) |
| **Expiry** | Checks whether the attestation's validity window has elapsed, allowing `clockSkew` seconds past `expiresAt`, and anchors the window to the signed `attestedAt`: `expiresAt` is bounded by `attestedAt` + 30 minutes (5 for a delegation verdict) plus the fixed 60-second binding grace (`EXPIRY_BINDING_GRACE_MS`, a verifier tolerance the spec permits), so a tampered future `expiresAt` cannot extend the window |
| **Post-quantum signature** | Verifies `pqSig` with ML-DSA-65 over the post-quantum domain tag plus the same classical preimage, key resolved by `pqKid`; in the JWT format, verifies `pqJwt` over its own `header.payload` and binds it to the `jwt` by the full claim set; always reported once the token parses and names the response's `kid`, including when a later check fails; reported as `verified`, `refuted`, `absent`, or `unverifiable` (spec Check 6). Needs the optional `@noble/post-quantum` peer; without it a present post-quantum signature is `unverifiable` |
| **Tokens in the response** (`checks.jwt`) | Only when a response object carries `data.jwt` beside `data.attestation`, which is what `format: "jwt"` returns. The tokens are verified too and bound to the attestation just verified: the ES256 signature of `jwt` under the same `kid`, its condition hashes, that it is the token of this attestation (`jti`, `pass`, `results`, `exp` equal the attestation's), and its post-quantum `pqJwt` over the full claim set, reported as `checks.jwt.pq`. A failure fails `valid`. Absent from the result when the response carries no tokens, so every other shape reports exactly the five verdicts above |

## What `valid` does not tell you

`valid: true` means InsumerAPI issued the artifact, it has not been modified, and it is still current. It does not mean access should be granted. Before acting on it, the relying party still has to:

1. **Check the verdict.** A validly signed attestation can say no. Read `pass` (or each `results[i].met`).
2. **Pin the conditions.** Compare every `results[i].evaluatedCondition` (or its `conditionHash`) with the conditions your route requires. Never trust `label`: the caller writes it.
3. **Bind the wallet.** The raw format signs no wallet for most condition types (only `erc8004_agent` and `erc7710_delegation` carry one, inside `evaluatedCondition`), so a raw attestation does not show whose wallet was read. Either call the API from your own server for a wallet the user has proved control of (for example by signing a one-time challenge), or require `format: "jwt"` and match `sub` against that proven wallet. `sub` names only the first evaluated chain family, in the order EVM, Solana, XRPL, Bitcoin, Tron, Stellar, Sui; wallets of other families in the same request are evaluated but not named.
4. **Reject replays by id.** Remember each attestation `id` (JWT `jti`) until it expires and refuse it a second time (spec Section 13.2). Never deduplicate on the signature or the token bytes: a different valid signature over the same bytes can be derived from a genuine one without the key.
5. **Treat only signed fields as evidence.** The signature covers `id`, `pass`, `results` and `attestedAt`. `passCount`, `failCount`, `expiresAt`, `ok` and `meta` are outside it. `expiresAt` is bound to `attestedAt` by Check 4; derive counts from `results` if you need them.

[`examples/express-gate.mjs`](./examples/express-gate.mjs) applies all five.

## Preimages and hashes, exactly as implemented

The `kid` on a response selects the scheme, and the scheme fixes the exact bytes that were signed and hashed. What follows is what this library computes, so a third party can reproduce every check without it.

**Canonical JSON (v2).** `canonicalize(value)`: arrays keep their order and canonicalize each element; objects emit their keys sorted lexicographically (`Object.keys(o).sort()`), each as `JSON.stringify(key) + ":" + canonicalize(value)`, joined by commas inside braces; every other value is `JSON.stringify(value)`. No whitespace. The sort is applied at every nesting level.

**Attestation signature preimage (raw format).**

- `insumer-attest-v1`: `JSON.stringify({ id, pass, results, attestedAt })`, in that insertion order, with `results` exactly as received (their own key order preserved). `expiresAt` is not in the preimage.
- `insumer-attest-v2`: `"insumer.attestation.v2" + "\n" + canonicalize({ v: 2, id, pass, results, attestedAt })`.

The ECDSA P-256 / SHA-256 signature (`sig`, base64, P1363 `r || s`) is verified over the UTF-8 bytes of that string.

**JWT format.** ES256 over the compact-serialization signing input `headerB64 + "." + payloadB64`; a DER-encoded signature is converted to P1363 first. The header `kid` selects the condition-hash scheme for the `results` claim.

**Trust profile signature preimage.**

- `insumer-attest-v1`: `JSON.stringify(trust)`, the whole `trust` object as parsed from the wire, insertion order preserved (which is why the object must not be rebuilt).
- `insumer-trust-v2`: `"insumer.trust.v2" + "\n" + canonicalize(trust)`, the whole object, `expiresAt` included, no `v` member.

**Condition hash (`conditionHash` on every attestation result).**

- v1 (`insumer-attest-v1`): `JSON.stringify(evaluatedCondition, Object.keys(evaluatedCondition).sort())`. The sorted top-level key list is passed as the replacer array, so the top-level keys are emitted in sorted order. A replacer array applies at every nesting level, so a nested object would be filtered to those same key names; for a flat `evaluatedCondition` the output is identical to canonical JSON.
- v2 (`insumer-attest-v2`): `canonicalize(evaluatedCondition)`, the recursive form above. In a v2 `evaluatedCondition`, `threshold` is a canonical decimal string and there is no `decimals` field.

In both eras the hash is `"0x" + hex(SHA-256(UTF-8 bytes))` and must equal the result's `conditionHash`; a result lacking `evaluatedCondition` or `conditionHash` fails the check at its index.

**Post-quantum signature.**

- Raw format: `pqSig` (base64) is an ML-DSA-65 signature over the UTF-8 bytes of `"insumer.attestation.pq1" + "\n" + <the classical preimage the classical kid selects>`; for a trust profile the tag is `"insumer.trust.pq1"` over the classical trust preimage. The key is the RFC 9964 `AKP` entry the JWKS lists under `pqKid` (`insumer-attest-pq1` or `insumer-trust-pq1`).
- JWT format: `pqJwt` is a compact JWS with `alg: "ML-DSA-65"`, verified over its own `headerB64 + "." + payloadB64`, then bound to the ES256 JWT by the full claim set: the two payloads must carry the same member names, and for every member a deeply equal JSON value (objects compared without regard to member order, arrays in order). Any difference, whether a changed value, a missing member or an extra one on either side, makes the post-quantum signature `refuted`, and the reason names the first differing claim. So the post-quantum signature vouches for every claim a relying party reads from the `jwt` (`sub`, `results`, `conditionHash` and the block anchor included), and cannot be transplanted from another artifact. Byte-identical payload segments satisfy the rule trivially; byte identity is never required.

None of the classical preimages changed when the post-quantum signature was added, and nothing else is ever appended to them.

## Examples

The [`examples/`](./examples/) directory contains runnable scripts covering common patterns:

| Example | What it shows |
|---------|--------------|
| [`basic-attest.mjs`](./examples/basic-attest.mjs) | Single token balance check + verification |
| [`multi-condition.mjs`](./examples/multi-condition.mjs) | Multiple conditions across different chains |
| [`jwt-format.mjs`](./examples/jwt-format.mjs) | JWT format for gateway integration (signature check only; see "What `valid` does not tell you") |
| [`verify-manual.mjs`](./examples/verify-manual.mjs) | DIY verification with Web Crypto — no library, proving the format is open |
| [`express-gate.mjs`](./examples/express-gate.mjs) | Express route gated on an attestation: server-chosen conditions, proven wallet, replay check |
| [`xrpl-trustline.mjs`](./examples/xrpl-trustline.mjs) | XRPL trust line tokens (RLUSD, USDC) |
| [`verify-trust.mjs`](./examples/verify-trust.mjs) | Trust profile verification + batch |

From a clone of this repository, build first, then run the examples from the repo root (they import the package by name, which resolves to the local build):

```bash
npm ci && npm run build
INSUMER_API_KEY=insr_live_... node examples/basic-attest.mjs
```

In your own project, `npm install insumer-verify` instead.

The attestation format is an open standard — `verify-manual.mjs` demonstrates full verification using only the Web Crypto API with no dependencies. See the [State Attestation Spec](https://insumermodel.com/state-attestation-spec) for the complete format definition.

## Pricing

**Tiers:** Free (10 free verifications plus 100 requests a day) | Pro $29/mo (1,000 credits/mo, 10,000/day) | Enterprise $99/mo (5,000 credits/mo, 100,000/day)

**Volume discounts:** $5–$99 = $0.04/call (25 credits/$1) · $100–$499 = $0.03 (33/$1, 25% off) · $500+ = $0.02 (50/$1, 50% off)

**Platform wallets:**
- **EVM (USDC/USDT):** `0xAd982CB19aCCa2923Df8F687C0614a7700255a23`
- **Solana (USDC/USDT):** `6a1mLjefhvSJX1sEX8PTnionbE9DqoYjU6F6bNkT4Ydr`
- **Bitcoin:** `bc1qg7qnerdhlmdn899zemtez5tcx2a2snc0dt9dt0`
- **Tron (USDT-TRC20):** `TC5yvwkAMakkXtUxYiu2Yn1xbBcwYuD6cn`

**Supported payment chains:** Ethereum, Base, Polygon, Arbitrum, Optimism, BNB Chain, Avalanche, Solana, Bitcoin, Tron. Tokens sent on unsupported chains cannot be recovered. All purchases are final and non-refundable. [Full pricing →](https://insumermodel.com/pricing/)

## License

MIT
