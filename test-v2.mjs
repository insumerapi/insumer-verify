/**
 * v2 verification tests for insumer-verify.
 *
 * The v1 suite (test.mjs / test-jwt.mjs) is entirely kid "insumer-attest-v1".
 * This file exercises the v2 scheme end to end — kid "insumer-attest-v2",
 * the domain-separated object-mode signature preimage
 * ("insumer.attestation.v2" + "\n" + recursive-canonical JSON), and the
 * recursive-canonical conditionHash — in both object mode and JWT mode.
 *
 * Test 3 is the regression guard for the JWT path forwarding `kid` to the
 * conditionHash check: it uses a NESTED evaluatedCondition, the one shape
 * where the v1 array-replacer and the v2 recursive canonicalizer diverge.
 * Drop the kid forwarding in verifyJwt and Test 3 fails.
 *
 * No secrets: every key here is an ephemeral P-256 keypair generated at
 * runtime; addresses are public/well-known dummies.
 *
 * Run: node test-v2.mjs
 */

import { verifyAttestation } from "./build/index.js";

const subtle = globalThis.crypto.subtle;
const V2_DOMAIN = "insumer.attestation.v2";
const V2_KID = "insumer-attest-v2";

let passed = 0;
let failed = 0;
function assert(condition, name) {
  if (condition) { console.log(`  PASS: ${name}`); passed++; }
  else { console.log(`  FAIL: ${name}`); failed++; }
}

// ── Canonicalization (must match build/index.js canonicalize) ───────
function canonicalize(value) {
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]))
      .join(",") + "}";
  }
  return JSON.stringify(value);
}
async function sha256Hex(str) {
  const buf = await subtle.digest("SHA-256", new TextEncoder().encode(str));
  return "0x" + Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
const v2CondHash = (ec) => sha256Hex(canonicalize(ec));
// v1 server scheme: sorted-key array-replacer (top-level keys only)
const v1CondHash = (ec) => sha256Hex(JSON.stringify(ec, Object.keys(ec).sort()));

// ── Encoding / signing helpers ──────────────────────────────────────
const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const b64url = (str) =>
  btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlBytes = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function genKey() {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}
async function sign(privateKey, str) {
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(str));
  return new Uint8Array(sig);
}
// Install a mock JWKS that serves `publicKey` under each kid in `kids`.
function mockJwks(publicKey, kids) {
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (typeof url === "string" && url.includes("jwks")) {
      const jwk = await subtle.exportKey("jwk", publicKey);
      return {
        ok: true,
        json: async () => ({
          keys: kids.map((kid) => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, kid })),
        }),
      };
    }
    return original(url);
  };
  return () => { globalThis.fetch = original; };
}

const JWKS = "https://test.example.com/.well-known/jwks.json";
const DUMMY = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC, public

// Build a v2 object-mode response signed by `priv`, with a given kid.
async function makeV2Object(priv, { kid = V2_KID, evaluatedCondition, tamperHash = false } = {}) {
  const now = new Date();
  const ec = evaluatedCondition || {
    type: "token_balance", chainId: 1, contractAddress: DUMMY, operator: "gte", threshold: "1000",
  };
  let conditionHash = await v2CondHash(ec);
  if (tamperHash) conditionHash = "0xdead" + conditionHash.slice(6);
  const results = [{
    condition: 0, label: "USDC >= 1000", type: ec.type, chainId: ec.chainId,
    met: true, evaluatedCondition: ec, conditionHash,
    blockNumber: "0x12a05f200", blockTimestamp: now.toISOString(),
  }];
  const attestation = {
    id: "ATST-V2TEST01", pass: true, results,
    attestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 1800000).toISOString(),
  };
  // v2 preimage signs { v:2, id, pass, results, attestedAt } (NOT expiresAt)
  const preimage = V2_DOMAIN + "\n" + canonicalize({
    v: 2, id: attestation.id, pass: attestation.pass, results: attestation.results, attestedAt: attestation.attestedAt,
  });
  const sig = b64(await sign(priv, preimage));
  return { data: { attestation, sig, kid } };
}

// Build a v2 JWT signed by `priv`, with a given kid + evaluatedCondition.
async function makeV2Jwt(priv, { kid = V2_KID, evaluatedCondition } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const ec = evaluatedCondition || {
    type: "token_balance", chainId: 1, contractAddress: DUMMY, operator: "gte", threshold: "1000",
  };
  const conditionHash = await v2CondHash(ec);
  const results = [{
    condition: 0, label: "USDC >= 1000", type: ec.type, chainId: ec.chainId,
    met: true, evaluatedCondition: ec, conditionHash,
    blockNumber: "0x12a05f200", blockTimestamp: new Date().toISOString(),
  }];
  const header = { alg: "ES256", typ: "JWT", kid };
  const payload = {
    iss: "https://api.insumermodel.com", sub: "0x1234567890abcdef1234567890abcdef12345678",
    jti: "ATST-V2TEST01", iat: now, exp: now + 1800, pass: true,
    conditionHash: [conditionHash], blockNumber: "0x12a05f200",
    blockTimestamp: new Date().toISOString(), results,
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = b64urlBytes(await sign(priv, signingInput));
  return `${signingInput}.${sig}`;
}

// ── Tests ────────────────────────────────────────────────────────

console.log("\nTest 1: Object-mode v2 — domain-separated sig + v2 conditionHash, all checks pass");
{
  const kp = await genKey();
  const restore = mockJwks(kp.publicKey, [V2_KID]);
  try {
    const resp = await makeV2Object(kp.privateKey);
    const r = await verifyAttestation(resp, { jwksUrl: JWKS });
    assert(r.checks.signature.passed, "v2 object signature passes (domain-separated preimage)");
    assert(r.checks.conditionHashes.passed, "v2 conditionHash passes (recursive canonical)");
    assert(r.checks.expiry.passed, "Expiry passes");
    assert(r.valid, "Overall valid");
  } finally { restore(); }
}

console.log("\nTest 2: JWT v2 — kid insumer-attest-v2, flat condition, valid");
{
  const kp = await genKey();
  const restore = mockJwks(kp.publicKey, [V2_KID]);
  try {
    const jwt = await makeV2Jwt(kp.privateKey);
    const r = await verifyAttestation(jwt, { jwksUrl: JWKS });
    assert(r.checks.signature.passed, "JWT v2 signature passes");
    assert(r.checks.conditionHashes.passed, "JWT v2 conditionHash passes");
    assert(r.valid, "Overall valid");
  } finally { restore(); }
}

console.log("\nTest 3: JWT v2 NESTED condition — regression guard for kid forwarding");
{
  // A nested evaluatedCondition is the one shape where the v1 array-replacer
  // and the v2 recursive canonicalizer produce different bytes. The server
  // doesn't emit nesting today, but this proves verifyJwt selects the v2
  // scheme by kid — i.e. that it forwards `kid` to checkConditionHashes.
  const nested = {
    type: "token_balance", chainId: 1, contractAddress: DUMMY, operator: "gte",
    threshold: "1000",
    meta: { source: "rpc", tier: { name: "gold", min: "1000" } }, // nested
  };
  const v1 = await v1CondHash(nested);
  const v2 = await v2CondHash(nested);
  assert(v1 !== v2, "Sanity: v1 and v2 canonicalization differ for a nested condition");

  const kp = await genKey();
  const restore = mockJwks(kp.publicKey, [V2_KID]);
  try {
    const jwt = await makeV2Jwt(kp.privateKey, { evaluatedCondition: nested });
    const r = await verifyAttestation(jwt, { jwksUrl: JWKS });
    assert(r.checks.signature.passed, "JWT signature passes");
    assert(r.checks.conditionHashes.passed, "v2 conditionHash passes ONLY if verifyJwt forwarded kid");
    assert(r.valid, "Overall valid");
  } finally { restore(); }
}

console.log("\nTest 4: Object-mode v2 — tampered conditionHash fails");
{
  const kp = await genKey();
  const restore = mockJwks(kp.publicKey, [V2_KID]);
  try {
    const resp = await makeV2Object(kp.privateKey, { tamperHash: true });
    const r = await verifyAttestation(resp, { jwksUrl: JWKS });
    assert(!r.checks.conditionHashes.passed, "Tampered v2 conditionHash should fail");
    assert(r.checks.conditionHashes.failures?.includes(0), "Should report index 0 as failure");
    assert(!r.valid, "Overall invalid");
  } finally { restore(); }
}

console.log("\nTest 5: Mislabeled kid — v2-signed but kid says insumer-attest-v1 → scheme mismatch fails");
{
  const kp = await genKey();
  // JWKS serves the key under BOTH kids, so key lookup succeeds; the failure
  // must come from scheme selection, not a missing key.
  const restore = mockJwks(kp.publicKey, ["insumer-attest-v1", V2_KID]);
  try {
    // Sign with the v2 preimage but label the response kid v1.
    const resp = await makeV2Object(kp.privateKey, { kid: "insumer-attest-v1" });
    const r = await verifyAttestation(resp, { jwksUrl: JWKS });
    assert(!r.checks.signature.passed, "v2 sig must NOT verify under the v1 preimage");
    assert(!r.valid, "Overall invalid");
  } finally { restore(); }
}

console.log("\nTest 7: kid is mandatory and bound to the artifact type (1.8.2)");
{
  const kp = await genKey();
  const restore = mockJwks(kp.publicKey, ["insumer-attest-v1", V2_KID, "insumer-trust-v2"]);
  try {
    const noKid = await makeV2Object(kp.privateKey);
    delete noKid.data.kid;
    let r = await verifyAttestation(noKid, { jwksUrl: JWKS });
    assert(!r.valid && !r.checks.signature.passed && /no kid/.test(r.checks.signature.reason), "missing kid with jwksUrl fails closed, no fallback to keys[0]");
    r = await verifyAttestation(noKid);
    assert(!r.valid && !r.checks.signature.passed && /no kid/.test(r.checks.signature.reason), "missing kid in default mode fails closed");
    const trustKid = await makeV2Object(kp.privateKey, { kid: "insumer-trust-v2" });
    r = await verifyAttestation(trustKid, { jwksUrl: JWKS });
    assert(!r.valid && /does not sign attestations/.test(r.checks.signature.reason), "a trust kid on an attestation fails Check 1");
    const jwt = await makeV2Jwt(kp.privateKey, { kid: "insumer-trust-v2" });
    r = await verifyAttestation(jwt, { jwksUrl: JWKS });
    assert(!r.valid && /does not sign attestations/.test(r.checks.signature.reason), "a trust kid in a JWT header fails Check 1");
    const good = await makeV2Object(kp.privateKey);
    r = await verifyAttestation(good, { jwksUrl: JWKS });
    assert(r.checks.signature.passed && r.checks.conditionHashes.passed, "control: the same fixture under its own kid verifies");
  } finally { restore(); }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
