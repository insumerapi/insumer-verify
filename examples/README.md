# insumer-verify examples

Runnable examples showing how to request, verify, and gate access with InsumerAPI attestations.

## Philosophy

InsumerAPI standardizes the **format and verification model** of eligibility attestations, not the underlying computation method. Any conforming implementation may use direct reads, proof systems, or delegated verification, but it must emit a privacy-preserving, signed, time-bounded attestation that can be independently verified by relying parties without real-time issuer communication.

What this means in practice: every example below produces or consumes the same signed attestation format. The verification side never needs to know *how* the attestation was produced — only that it conforms to the [State Attestation Spec](https://insumermodel.com/state-attestation-spec).

## Examples

| File | What it shows |
|------|--------------|
| `basic-attest.mjs` | Single token balance check + verification |
| `multi-condition.mjs` | Multiple conditions across different chains |
| `jwt-format.mjs` | Request JWT format for gateway integration (signature check only; see the main README) |
| `verify-manual.mjs` | DIY verification with Web Crypto — no library, proving the format is open |
| `express-gate.mjs` | Express route gated on an attestation: server-chosen conditions, proven wallet, replay check |
| `xrpl-trustline.mjs` | XRPL trust line tokens (RLUSD, USDC) with issuer addressing |
| `verify-trust.mjs` | Trust profile verification (evidence by dimension) + batch |

## Prerequisites

From a clone of this repository, build the library first and run the examples from the repo root (they import `insumer-verify` by name, which resolves to the local build):

```bash
npm ci && npm run build
```

In your own project, install it instead:

```bash
npm install insumer-verify
```

`express-gate.mjs` also needs `npm install express`.

Get a free API key:

```bash
curl -s -X POST https://api.insumermodel.com/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "appName": "examples", "tier": "free"}' | jq .
```

Set it as an environment variable:

```bash
export INSUMER_API_KEY=insr_live_your_key_here
```

## Run

```bash
node examples/basic-attest.mjs
node examples/verify-manual.mjs   # no library needed
```

## Verification spec

All examples verify attestations against the [State Attestation Specification](https://insumermodel.com/state-attestation-spec). The spec defines:

- **Attestation format** — signed boolean assertions over on-chain state
- **Signing scheme** — ECDSA P-256 (ES256) with JWKS key distribution
- **Condition hashes** — SHA-256 tamper seals over evaluated predicates
- **Verification algorithm** — the four core checks (spec Section 12; Checks 5 and 6 are optional), which any relying party can run offline

The format is the standard. The computation behind it is an implementation detail.
