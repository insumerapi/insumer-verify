/**
 * Trust-profile verification tests for insumer-verify.
 *
 * Covers POST /v1/trust (and /v1/trust/batch entries) under both schemes:
 *   insumer-attest-v1 → bare JSON.stringify(trust)            (v1, frozen)
 *   insumer-trust-v2  → "insumer.trust.v2\n" + canonical JSON (v2, domain-separated)
 *
 * Test 5 is the domain-separation guard: a signature made over the ATTEST
 * domain must not verify as a trust profile, even though both message types
 * share one key. Test 11/12 are the scheme-difference guard: reordering the
 * payload's keys breaks v1 (insertion-order preimage) but not v2 (canonical).
 *
 * No secrets: every key here is an ephemeral P-256 keypair generated at
 * runtime; the wallet is a public/well-known dummy address.
 *
 * Run: node test-trust.mjs
 */

import { verifyTrustProfile } from "./build/index.js";

const subtle = globalThis.crypto.subtle;
const V2_TRUST_DOMAIN = "insumer.trust.v2";
const V2_TRUST_KID = "insumer-trust-v2";
const V1_KID = "insumer-attest-v1";
const V2_ATTEST_DOMAIN = "insumer.attestation.v2";

let passed = 0;
let failed = 0;
function assert(condition, name) {
  if (condition) { console.log(`  PASS: ${name}`); passed++; }
  else { console.log(`  FAIL: ${name}`); failed++; }
}

// Must match build/index.js canonicalize (recursive sorted-key).
function canonicalize(value) {
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]))
      .join(",") + "}";
  }
  return JSON.stringify(value);
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

async function genKey() {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}
// Web Crypto ECDSA emits P1363 (raw r||s), the encoding the API's sig field uses.
async function sign(privateKey, str) {
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(str));
  return b64(new Uint8Array(sig));
}

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
const WALLET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC contract, public

/**
 * Build a trust payload in the key order the API constructs it:
 * id, wallet, conditionSetVersion, dimensions, summary, profiledAt, expiresAt.
 */
function makeTrustPayload({ v2 = true, ageMs = 0, ttlMs = 30 * 60 * 1000, blockAgeMs = 0 } = {}) {
  const now = new Date(Date.now() - ageMs);
  const blockTs = new Date(Date.now() - blockAgeMs).toISOString();
  return {
    id: "trust_test_0001",
    wallet: WALLET,
    conditionSetVersion: v2 ? "v2" : "v1",
    // real backend shape: dimensions keyed by name, each with a checks[] array
    // whose entries carry an on-chain blockTimestamp (exercises nested freshness
    // + recursive canonicalization)
    dimensions: {
      onChainActivity: { checks: [{ label: "tx count", met: true, blockTimestamp: blockTs }] },
      tokenHoldings: { checks: [{ label: "USDC", met: true, blockTimestamp: blockTs }] },
    },
    summary: {
      totalChecks: 5,
      totalPassed: 4,
      totalFailed: 1,
      dimensionsWithActivity: 2,
      dimensionsChecked: 2,
    },
    profiledAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  };
}

const wrap = (trust, sig, kid) => ({ ok: true, data: { trust, sig, kid }, meta: {} });

console.log("\ninsumer-verify — trust profile suite\n");

const { privateKey: priv, publicKey: pub } = await genKey();
const restore = mockJwks(pub, [V1_KID, "insumer-attest-v2", V2_TRUST_KID]);

try {
  // 1. v2 happy path
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.valid === true, "v2 trust profile verifies");
    assert(r.checks.signature.passed === true, "v2 signature check passes");
    assert(r.checks.expiry.passed === true, "v2 expiry check passes");
  }

  // 2. v1 happy path (bare JSON.stringify, shared attest kid)
  {
    const trust = makeTrustPayload({ v2: false });
    const sig = await sign(priv, JSON.stringify(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V1_KID), { jwksUrl: JWKS });
    assert(r.valid === true, "v1 trust profile verifies");
  }

  // 3. tampered payload — v2
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const tampered = { ...trust, summary: { ...trust.summary, totalPassed: 5 } };
    const r = await verifyTrustProfile(wrap(tampered, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.valid === false && r.checks.signature.passed === false, "v2 tampered summary rejected");
  }

  // 4. tampered payload — v1
  {
    const trust = makeTrustPayload({ v2: false });
    const sig = await sign(priv, JSON.stringify(trust));
    const tampered = { ...trust, wallet: "0x0000000000000000000000000000000000000001" };
    const r = await verifyTrustProfile(wrap(tampered, sig, V1_KID), { jwksUrl: JWKS });
    assert(r.valid === false && r.checks.signature.passed === false, "v1 tampered wallet rejected");
  }

  // 5. DOMAIN SEPARATION — attest-domain signature must not verify as trust
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_ATTEST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.valid === false, "attest-domain signature rejected as trust profile");
  }

  // 6. scheme confusion — v2 bytes labelled with the v1 kid
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V1_KID), { jwksUrl: JWKS });
    assert(r.valid === false, "v2 bytes under v1 kid rejected");
  }

  // 7. expired profile
  {
    const trust = makeTrustPayload({ v2: true, ageMs: 60 * 60 * 1000, ttlMs: 30 * 60 * 1000 });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.checks.signature.passed === true, "expired profile still has a valid signature");
    assert(r.checks.expiry.passed === false && r.valid === false, "expired profile rejected");
  }

  // 8. freshness via maxAge
  {
    const trust = makeTrustPayload({ v2: true, ageMs: 10 * 60 * 1000, ttlMs: 60 * 60 * 1000 });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const stale = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60 });
    const fresh = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 3600 });
    assert(stale.checks.freshness.passed === false && stale.valid === false, "maxAge 60s rejects a 10min-old profile");
    assert(fresh.valid === true, "maxAge 3600s accepts a 10min-old profile");
  }

  // 9. batch-entry shape (no { data } wrapper)
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile({ trust, sig, kid: V2_TRUST_KID }, { jwksUrl: JWKS });
    assert(r.valid === true, "bare { trust, sig, kid } batch entry verifies");
  }

  // 10. malformed input
  {
    const a = await verifyTrustProfile({ ok: true, data: {} }, { jwksUrl: JWKS });
    const b = await verifyTrustProfile("not an object", { jwksUrl: JWKS });
    assert(a.valid === false, "missing trust rejected");
    assert(b.valid === false, "non-object rejected");
  }

  // 11. v1 is insertion-order sensitive (documents why trust is not rebuilt)
  {
    const trust = makeTrustPayload({ v2: false });
    const sig = await sign(priv, JSON.stringify(trust));
    const reordered = {
      expiresAt: trust.expiresAt,
      profiledAt: trust.profiledAt,
      summary: trust.summary,
      dimensions: trust.dimensions,
      conditionSetVersion: trust.conditionSetVersion,
      wallet: trust.wallet,
      id: trust.id,
    };
    const r = await verifyTrustProfile(wrap(reordered, sig, V1_KID), { jwksUrl: JWKS });
    assert(r.valid === false, "v1 rejects a key-reordered payload (insertion-order preimage)");
  }

  // 12. v2 is order-independent (canonical preimage)
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const reordered = {
      expiresAt: trust.expiresAt,
      profiledAt: trust.profiledAt,
      summary: trust.summary,
      dimensions: trust.dimensions,
      conditionSetVersion: trust.conditionSetVersion,
      wallet: trust.wallet,
      id: trust.id,
    };
    const r = await verifyTrustProfile(wrap(reordered, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.valid === true, "v2 accepts a key-reordered payload (canonical preimage)");
  }

  // 13. wrong key entirely
  {
    const other = await genKey();
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(other.privateKey, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.valid === false, "signature from a foreign key rejected");
  }

  // ── Fix 1: structural gate against the shared v1 kid ────────────────

  // 14. a validly v1-signed object of another type must NOT pass as a trust profile
  {
    const now = new Date();
    const otherArtifact = {
      kind: "other-v1-artifact", value: 1,
      expiresAt: new Date(now.getTime() + 1800000).toISOString(),
    };
    const sig = await sign(priv, JSON.stringify(otherArtifact)); // genuine v1 signature
    const r = await verifyTrustProfile(wrap(otherArtifact, sig, V1_KID), { jwksUrl: JWKS });
    assert(r.valid === false, "validly-signed object of another type rejected (not trust-shaped)");
    assert(/not a trust profile/i.test(r.checks.signature.reason || ""), "rejection cites shape, not crypto");
  }

  // 15. a genuine attestation object, validly signed v1, must NOT pass as trust
  {
    const now = new Date();
    const attn = {
      id: "att_1", pass: true, results: [], attestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 1800000).toISOString(),
    };
    const sig = await sign(priv, JSON.stringify(attn));
    const r = await verifyTrustProfile(wrap(attn, sig, V1_KID), { jwksUrl: JWKS });
    assert(r.valid === false, "validly-signed attestation rejected (not trust-shaped)");
  }

  // ── Fix 2: the verified object is returned ──────────────────────────

  // 16. result.trust echoes the exact verified profile on success; absent on parse-fail
  {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.valid === true && r.trust && r.trust.wallet === WALLET && r.trust.id === trust.id,
      "result.trust returns the verified profile");
    const bad = await verifyTrustProfile({ ok: true, data: {} }, { jwksUrl: JWKS });
    assert(bad.trust === undefined, "result.trust is undefined when parsing fails");
  }

  // ── Fix 3: nested on-chain blockTimestamp freshness ─────────────────

  // 17. profiledAt fresh, but a dimension's on-chain read is stale → fails freshness
  {
    const trust = makeTrustPayload({ v2: true, ageMs: 0, blockAgeMs: 10 * 60 * 1000 });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60 });
    assert(r.checks.signature.passed === true, "stale-block profile still has a valid signature");
    assert(r.checks.freshness.passed === false && r.valid === false, "stale nested blockTimestamp fails freshness");
    assert(/on-chain data/i.test(r.checks.freshness.reason || ""), "freshness reason names the on-chain staleness");
  }

  // 18. profiledAt and nested blockTimestamp both fresh → passes under maxAge
  {
    const trust = makeTrustPayload({ v2: true, ageMs: 5000, blockAgeMs: 5000 });
    const sig = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    const r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 3600 });
    assert(r.valid === true, "fresh profiledAt + fresh nested block passes under maxAge");
  }

  // ── Clock-skew allowance (options.clockSkew, default 60s; spec Section 9.4) ──

  // 19. expiry: 30s past expiresAt is inside the default allowance; clockSkew: 0 refuses it;
  //     90s past is beyond it
  {
    const within = makeTrustPayload({ v2: true, ageMs: 30 * 60 * 1000 + 30000, ttlMs: 30 * 60 * 1000 });
    const sigW = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(within));
    let r = await verifyTrustProfile(wrap(within, sigW, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.checks.expiry.passed === true && r.valid === true, "30s past expiresAt passes under the default 60s skew");
    r = await verifyTrustProfile(wrap(within, sigW, V2_TRUST_KID), { jwksUrl: JWKS, clockSkew: 0 });
    assert(r.checks.expiry.passed === false && r.valid === false, "30s past expiresAt fails with clockSkew: 0");

    const beyond = makeTrustPayload({ v2: true, ageMs: 30 * 60 * 1000 + 90000, ttlMs: 30 * 60 * 1000 });
    const sigB = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(beyond));
    r = await verifyTrustProfile(wrap(beyond, sigB, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.checks.expiry.passed === false && r.valid === false, "90s past expiresAt fails under the default 60s skew");
  }

  // 20. freshness: the allowance is added to maxAge on profiledAt and on nested blockTimestamps
  {
    const profile = makeTrustPayload({ v2: true, ageMs: 100000, blockAgeMs: 0, ttlMs: 60 * 60 * 1000 });
    const sigP = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(profile));
    let r = await verifyTrustProfile(wrap(profile, sigP, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60 });
    assert(r.checks.freshness.passed === true, "100s-old profiledAt passes maxAge 60 under the default 60s skew");
    r = await verifyTrustProfile(wrap(profile, sigP, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60, clockSkew: 0 });
    assert(r.checks.freshness.passed === false, "100s-old profiledAt fails maxAge 60 with clockSkew: 0");

    const block = makeTrustPayload({ v2: true, ageMs: 0, blockAgeMs: 100000, ttlMs: 60 * 60 * 1000 });
    const sigK = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(block));
    r = await verifyTrustProfile(wrap(block, sigK, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60 });
    assert(r.checks.freshness.passed === true, "100s-old nested block passes maxAge 60 under the default 60s skew");
    r = await verifyTrustProfile(wrap(block, sigK, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60, clockSkew: 0 });
    assert(r.checks.freshness.passed === false && /on-chain data/i.test(r.checks.freshness.reason || ""),
      "100s-old nested block fails maxAge 60 with clockSkew: 0");
    const beyond = makeTrustPayload({ v2: true, ageMs: 0, blockAgeMs: 130000, ttlMs: 60 * 60 * 1000 });
    const sigX = await sign(priv, V2_TRUST_DOMAIN + "\n" + canonicalize(beyond));
    r = await verifyTrustProfile(wrap(beyond, sigX, V2_TRUST_KID), { jwksUrl: JWKS, maxAge: 60 });
    assert(r.checks.freshness.passed === false, "130s-old nested block fails maxAge 60 under the default 60s skew");
  }
} finally {
  restore();
}

console.log("\n  kid is mandatory and bound to the artifact type (1.8.2)");
{
  const kp = await genKey();
  const restore2 = mockJwks(kp.publicKey, ["insumer-attest-v1", "insumer-attest-v2", V2_TRUST_KID]);
  try {
    const trust = makeTrustPayload({ v2: true });
    const sig = await sign(kp.privateKey, V2_TRUST_DOMAIN + "\n" + canonicalize(trust));
    let r = await verifyTrustProfile(wrap(trust, sig, undefined), { jwksUrl: JWKS });
    assert(!r.valid && /no kid/.test(r.checks.signature.reason), "missing kid on a trust profile fails closed");
    r = await verifyTrustProfile(wrap(trust, sig, "insumer-attest-v2"), { jwksUrl: JWKS });
    assert(!r.valid && /does not sign trust profiles/.test(r.checks.signature.reason), "an attestation v2 kid on a trust profile fails Check 1");
    r = await verifyTrustProfile(wrap(trust, sig, V2_TRUST_KID), { jwksUrl: JWKS });
    assert(r.checks.signature.passed, "control: the same profile under insumer-trust-v2 verifies");
  } finally { restore2(); }
}

console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
