/**
 * verify-manual.mjs — DIY attestation verification with Web Crypto.
 *
 * No library. No dependencies. Just the Web Crypto API and the spec.
 *
 * This example proves that the attestation format is open and independently
 * verifiable. You don't need insumer-verify, you don't need to trust any
 * library — you can verify directly against the JWKS public key using
 * standard cryptographic primitives available in every modern runtime.
 *
 * The protocol standardizes the format and verification model, not the
 * implementation. This file IS a conforming verifier.
 *
 * Implements the four core verification checks from the State Attestation Spec
 * (Section 12; Checks 5 and 6 are optional):
 *   1. Signature — ECDSA P-256; the preimage depends on the response kid:
 *        kid "insumer-attest-v2" (every key minted today):
 *          "insumer.attestation.v2\n" + canonical JSON (recursive sorted
 *          keys) of {v: 2, id, pass, results, attestedAt}
 *        kid "insumer-attest-v1" (pre-cutover keys):
 *          JSON.stringify({id, pass, results, attestedAt}) in that exact
 *          field order, keys unsorted
 *   2. Condition hashes — SHA-256 of canonical sorted-key JSON
 *   3. Freshness — blockTimestamp age vs maxAge
 *   4. Expiry — attestation validity window
 *
 * Usage: INSUMER_API_KEY=insr_live_... node examples/verify-manual.mjs
 */

const API_KEY = process.env.INSUMER_API_KEY;
if (!API_KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// ── Canonical JSON: recursive sorted keys ────────────────────────
// Used for the v2 signature preimage and for condition hashes.

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

// ── Step 2: Request an attestation ───────────────────────────────
// (threshold is a decimal string: keys minted today sign under the v2
// scheme and reject a JSON number with 400)

const res = await fetch("https://api.insumermodel.com/v1/attest", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  },
  body: JSON.stringify({
    wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    conditions: [
      {
        type: "token_balance",
        chainId: 1,
        contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        threshold: "100",
        label: "USDC >= 100 on Ethereum",
      },
    ],
  }),
});

const apiResponse = await res.json();
if (!apiResponse.ok) {
  console.error("API error:", apiResponse.error);
  process.exit(1);
}

const { attestation, sig, kid } = apiResponse.data;
console.log("Received attestation:", attestation.id, "(kid:", kid + ")");

// ── Step 1 (deferred until we know the kid): resolve the key ─────
// Never take keys[0]: select the JWKS entry whose kid matches the
// response. The set is the trust boundary; the kid picks within it.

const jwksRes = await fetch("https://api.insumermodel.com/v1/jwks");
const jwks = await jwksRes.json();
const keyData = jwks.keys.find((k) => k.kid === kid);
if (!keyData) {
  console.error(`No JWKS key matches kid "${kid}" — refusing to verify.`);
  process.exit(1);
}

const publicKey = await crypto.subtle.importKey(
  "jwk",
  { kty: keyData.kty, crv: keyData.crv, x: keyData.x, y: keyData.y },
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["verify"]
);

console.log("Resolved public key by kid:", keyData.kid);

// ── Check 1: Signature verification (preimage per kid) ───────────

let signedPayload;
if (kid === "insumer-attest-v2") {
  signedPayload =
    "insumer.attestation.v2\n" +
    canonicalJson({
      v: 2,
      id: attestation.id,
      pass: attestation.pass,
      results: attestation.results,
      attestedAt: attestation.attestedAt,
    });
} else if (kid === "insumer-attest-v1") {
  // v1 signs the keys in their original order. Do NOT sort them.
  signedPayload = JSON.stringify({
    id: attestation.id,
    pass: attestation.pass,
    results: attestation.results,
    attestedAt: attestation.attestedAt,
  });
} else {
  console.error(`Unknown attestation kid "${kid}" — refusing to verify.`);
  process.exit(1);
}

const payloadBytes = new TextEncoder().encode(signedPayload);
const sigBytes = Uint8Array.from(atob(sig), (c) => c.charCodeAt(0));

const sigValid = await crypto.subtle.verify(
  { name: "ECDSA", hash: "SHA-256" },
  publicKey,
  sigBytes,
  payloadBytes
);

console.log("\nCheck 1 — Signature:", sigValid ? "PASSED" : "FAILED");

// ── Check 2: Condition hash integrity ────────────────────────────
// Each result's conditionHash must equal SHA-256 of its evaluatedCondition
// serialized with recursively sorted keys.

let hashesValid = true;
for (const r of attestation.results) {
  const canonical = canonicalJson(r.evaluatedCondition);
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical)
  );
  const computed =
    "0x" +
    Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  if (computed !== r.conditionHash) {
    console.log(`Check 2 — Condition hash MISMATCH at index ${r.condition}`);
    console.log(`  Expected: ${r.conditionHash}`);
    console.log(`  Computed: ${computed}`);
    hashesValid = false;
  }
}
console.log("Check 2 — Condition hashes:", hashesValid ? "PASSED" : "FAILED");

// ── Check 3: Freshness ───────────────────────────────────────────
// Reject if blockTimestamp is older than maxAge seconds.

const MAX_AGE_SECONDS = 120;
let freshnessValid = true;
for (const r of attestation.results) {
  if (!r.blockTimestamp) continue; // skip chains without block timestamps
  const ageMs = Date.now() - new Date(r.blockTimestamp).getTime();
  if (ageMs > MAX_AGE_SECONDS * 1000) {
    console.log(
      `Check 3 — Result ${r.condition} is ${Math.round(ageMs / 1000)}s old (max: ${MAX_AGE_SECONDS}s)`
    );
    freshnessValid = false;
  }
}
console.log("Check 3 — Freshness:", freshnessValid ? "PASSED" : "FAILED");

// ── Check 4: Expiry ──────────────────────────────────────────────
// Reject if the validity window has elapsed. Anchor to the SIGNED attestedAt,
// not the wire expiresAt alone: expiresAt sits outside the signed preimage, so a
// verifier that trusts it can be replayed with a future-dated value. The API never
// issues a window longer than 30 min (5 for a delegation verdict), so bound it.
const attestedAtMs = new Date(attestation.attestedAt).getTime();
const expiresAtMs = new Date(attestation.expiresAt).getTime();
const hasDelegation = (attestation.results || []).some(
  (r) => r.evaluatedCondition && r.evaluatedCondition.type === "erc7710_delegation"
);
const maxWindowMs = (hasDelegation ? 5 : 30) * 60 * 1000 + 60 * 1000; // + grace
const expiryValid =
  expiresAtMs - attestedAtMs <= maxWindowMs && Date.now() <= expiresAtMs;
console.log("Check 4 — Expiry:", expiryValid ? "PASSED" : "FAILED");

// ── Summary ──────────────────────────────────────────────────────

const allPassed = sigValid && hashesValid && freshnessValid && expiryValid;
console.log("\nOverall:", allPassed ? "VALID" : "INVALID");
console.log(`Attestation ${attestation.id}: ${attestation.pass ? "conditions met" : "conditions not met"}`);
