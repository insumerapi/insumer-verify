/**
 * JWT verification tests for insumer-verify.
 *
 * Tests the JWT input path: auto-detection, signature verification,
 * condition hash integrity, freshness, and expiry checks via JWT claims.
 *
 * Run: node test-jwt.mjs
 */

import { verifyAttestation } from "./build/index.js";

const subtle = globalThis.crypto.subtle;

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    console.log(`  PASS: ${name}`);
    passed++;
  } else {
    console.log(`  FAIL: ${name}`);
    failed++;
  }
}

// ── Helpers ──────────────────────────────────────────────────────

function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesToBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createTestJwt(overrides = {}) {
  const keyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const now = Math.floor(Date.now() / 1000);

  // Build evaluatedCondition (matches the API's format)
  const evaluatedCondition = {
    type: "token_balance",
    chainId: 1,
    contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    operator: "gte",
    threshold: "1000000",
    decimals: 6,
  };

  // Compute conditionHash
  const sortedKeys = Object.keys(evaluatedCondition).sort();
  const canonical = JSON.stringify(evaluatedCondition, sortedKeys);
  const hashBuf = await subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const conditionHash =
    "0x" +
    Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  const results = [
    {
      condition: 0,
      label: "USDC >= 1",
      type: "token_balance",
      chainId: 1,
      met: true,
      evaluatedCondition,
      conditionHash,
      blockNumber: "0x12a05f200",
      blockTimestamp: new Date().toISOString(),
      ...(overrides.resultOverrides || {}),
    },
  ];

  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: "insumer-attest-v1",
    ...(overrides.headerOverrides || {}),
  };

  const payload = {
    iss: "https://api.insumermodel.com",
    sub: "0x1234567890abcdef1234567890abcdef12345678",
    jti: "ATST-TEST1",
    iat: now,
    exp: now + 1800,
    pass: true,
    conditionHash: [conditionHash],
    blockNumber: "0x12a05f200",
    blockTimestamp: new Date().toISOString(),
    results,
    ...(overrides.payloadOverrides || {}),
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const sigBuffer = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    signingInput
  );

  // Web Crypto sign returns P1363 format (raw r||s, 64 bytes)
  const sigB64 = bytesToBase64Url(new Uint8Array(sigBuffer));

  const jwt = `${headerB64}.${payloadB64}.${sigB64}`;

  return { jwt, keyPair, header, payload };
}

// Create a mock JWKS fetch that returns the test key
function mockFetchForKey(publicKey) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (typeof url === "string" && url.includes("jwks")) {
      const jwk = await subtle.exportKey("jwk", publicKey);
      return {
        ok: true,
        json: async () => ({
          keys: [
            {
              kty: jwk.kty,
              crv: jwk.crv,
              x: jwk.x,
              y: jwk.y,
              kid: "insumer-attest-v1",
            },
          ],
        }),
      };
    }
    return originalFetch(url);
  };
  return () => {
    globalThis.fetch = originalFetch;
  };
}

// ── Tests ────────────────────────────────────────────────────────

// Test 1: Auto-detection — string input goes to JWT path
console.log("\nTest 1: Auto-detection — string input goes to JWT path");
{
  const { jwt, keyPair } = await createTestJwt();
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    const result = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
    });
    assert(result.checks.signature.passed, "JWT signature should pass with matching key");
    assert(result.checks.conditionHashes.passed, "Condition hashes should pass");
    assert(result.checks.expiry.passed, "Expiry should pass");
    assert(result.valid, "Overall should be valid");
  } finally {
    restore();
  }
}

// Test 2: Auto-detection — object input goes to existing path
console.log("\nTest 2: Auto-detection — object input goes to existing path");
{
  const result = await verifyAttestation({ data: { attestation: { id: "ATST-X", pass: true, results: [], attestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 1800000).toISOString() }, sig: "dGVzdA==" } });
  // Signature will fail (not signed by InsumerAPI key), but the point is it didn't
  // try to parse as JWT
  assert(!result.checks.signature.passed, "Sig fails (test sig, not InsumerAPI)");
  assert(result.checks.conditionHashes.passed, "Condition hashes pass (empty results)");
  assert(result.checks.expiry.passed, "Expiry passes");
}

// Test 3: JWT with valid signature, all 4 checks pass
console.log("\nTest 3: Valid JWT — all 4 checks pass");
{
  const { jwt, keyPair } = await createTestJwt();
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    const result = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
      maxAge: 300,
    });
    assert(result.checks.signature.passed, "Signature passes");
    assert(result.checks.conditionHashes.passed, "Condition hashes pass");
    assert(result.checks.freshness.passed, "Freshness passes");
    assert(result.checks.expiry.passed, "Expiry passes");
    assert(result.valid, "Overall valid");
  } finally {
    restore();
  }
}

// Test 4: Tampered JWT payload — signature fails
console.log("\nTest 4: Tampered JWT payload — signature fails");
{
  const { jwt, keyPair } = await createTestJwt();
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    // Tamper with the payload by changing a character
    const parts = jwt.split(".");
    // Decode payload, modify, re-encode
    const payloadJson = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    payloadJson.pass = false; // tamper
    const tamperedPayload = btoa(JSON.stringify(payloadJson))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const tamperedJwt = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const result = await verifyAttestation(tamperedJwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
    });
    assert(!result.checks.signature.passed, "Signature should fail for tampered JWT");
    assert(!result.valid, "Overall should be invalid");
  } finally {
    restore();
  }
}

// Test 5: Expired JWT — exp in the past (5 min: beyond the default 60s clock skew)
console.log("\nTest 5: Expired JWT — expiry check fails");
{
  const { jwt, keyPair } = await createTestJwt({
    payloadOverrides: { exp: Math.floor(Date.now() / 1000) - 300 }, // 5 min ago
  });
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    const result = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
    });
    assert(!result.checks.expiry.passed, "Expiry should fail for expired JWT");
    assert(!result.valid, "Overall should be invalid");
  } finally {
    restore();
  }
}

// Test 5b: exp 30s in the past is inside the default clock-skew allowance; clockSkew: 0 refuses it
console.log("\nTest 5b: JWT exp within the clock-skew allowance");
{
  const { jwt, keyPair } = await createTestJwt({
    payloadOverrides: { exp: Math.floor(Date.now() / 1000) - 30 }, // 30s ago
  });
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    const lenient = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
    });
    assert(lenient.checks.expiry.passed, "exp 30s ago passes under the default 60s skew");
    const strict = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
      clockSkew: 0,
    });
    assert(!strict.checks.expiry.passed, "exp 30s ago fails with clockSkew: 0");
  } finally {
    restore();
  }
}

// Test 6: Stale blockTimestamp in JWT — freshness check fails
console.log("\nTest 6: Stale blockTimestamp — freshness check fails");
{
  const oldTimestamp = new Date(Date.now() - 120000).toISOString(); // 2 min ago
  const { jwt, keyPair } = await createTestJwt({
    resultOverrides: { blockTimestamp: oldTimestamp },
    payloadOverrides: { blockTimestamp: oldTimestamp },
  });
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    const result = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
      maxAge: 1, // 1 second — will fail
    });
    assert(!result.checks.freshness.passed, "Freshness should fail for stale blockTimestamp");
  } finally {
    restore();
  }
}

// Test 7: Tampered conditionHash in JWT — condition hash check fails
console.log("\nTest 7: Tampered conditionHash in JWT — hash check fails");
{
  const { jwt, keyPair } = await createTestJwt({
    resultOverrides: { conditionHash: "0xdeadbeefdeadbeefdeadbeefdeadbeef" },
  });
  const restore = mockFetchForKey(keyPair.publicKey);
  try {
    const result = await verifyAttestation(jwt, {
      jwksUrl: "https://test.example.com/.well-known/jwks.json",
    });
    assert(!result.checks.conditionHashes.passed, "Condition hash should fail");
    assert(
      result.checks.conditionHashes.failures?.includes(0),
      "Should report index 0 as failure"
    );
  } finally {
    restore();
  }
}

// Test 8: JWT sub matches wallet address
console.log("\nTest 8: JWT sub field contains wallet address");
{
  const wallet = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
  const { jwt } = await createTestJwt({
    payloadOverrides: { sub: wallet },
  });
  // Just verify we can parse the JWT and extract sub
  const parts = jwt.split(".");
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
  assert(payload.sub === wallet, "JWT sub should match wallet address");
}

// Test 9: JWT jti matches attestationId
console.log("\nTest 9: JWT jti matches attestation ID");
{
  const attestId = "ATST-X9Y2Z";
  const { jwt } = await createTestJwt({
    payloadOverrides: { jti: attestId },
  });
  const parts = jwt.split(".");
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
  assert(payload.jti === attestId, "JWT jti should match attestation ID");
}

// Test 10: JWT exp is exactly 1800s after iat
console.log("\nTest 10: JWT exp is 1800s after iat");
{
  const { jwt } = await createTestJwt();
  const parts = jwt.split(".");
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
  assert(payload.exp - payload.iat === 1800, "exp should be exactly 1800s after iat");
}

// Test 11: Invalid JWT string — parse error
console.log("\nTest 11: Invalid JWT string — returns parse error");
{
  const result = await verifyAttestation("not.a.valid-jwt!!!");
  assert(!result.valid, "Should be invalid");
  assert(
    result.checks.signature.reason?.includes("JWT parse error") ||
    result.checks.signature.reason?.includes("JWT signature"),
    "Should report parse or signature error"
  );
}

// Test 12: On the JWT path too, a kid that selects no key fails the signature verdict only
console.log("\nTest 12: JWT under a kid the key set does not hold — other verdicts stay independent");
{
  const { jwt, keyPair } = await createTestJwt({ headerOverrides: { kid: "insumer-attest-v9" } });
  const restore = mockFetchForKey(keyPair.publicKey); // serves insumer-attest-v1 only
  try {
    const result = await verifyAttestation(jwt, { jwksUrl: "https://test.example.com/.well-known/jwks.json" });
    assert(result.valid === false, "valid is false");
    assert(!result.checks.signature.passed && /no key matching kid/.test(result.checks.signature.reason), "signature carries the key-selection reason");
    assert(result.checks.conditionHashes.passed, "condition hashes are recomputed from the claims and reproduce");
    assert(result.checks.expiry.passed, "expiry reports its own result");
    assert(result.checks.pq.status === "absent", "no companion supplied: pq is absent");
  } finally {
    restore();
  }
  const missing = await createTestJwt({ headerOverrides: { kid: undefined } });
  const restore2 = mockFetchForKey(missing.keyPair.publicKey);
  try {
    const result = await verifyAttestation(missing.jwt, { jwksUrl: "https://test.example.com/.well-known/jwks.json" });
    assert(result.valid === false && /no kid/.test(result.checks.signature.reason), "missing kid: valid is false, the signature verdict says so");
    assert(result.checks.conditionHashes.passed && result.checks.expiry.passed, "missing kid: condition hashes and expiry still report their own results");
  } finally {
    restore2();
  }
}

// ── Summary ──────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
