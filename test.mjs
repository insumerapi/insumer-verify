/**
 * Self-contained test for insumer-verify.
 *
 * Tests the library against a real-format attestation by generating a
 * test P-256 keypair, signing a payload, then verifying it. Also tests
 * condition hash computation, freshness, and expiry checks.
 *
 * Run: node test.mjs
 */

import { verifyAttestation } from "./build/index.js";

const subtle = globalThis.crypto.subtle;

// ── Helper: generate a test keypair and sign ───────────────────────

async function generateTestAttestation(overrides = {}) {
  const keyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 60 * 1000);

  // Build evaluatedCondition (matches the API's format)
  const evaluatedCondition = {
    type: "token_balance",
    chainId: 1,
    contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    operator: "gte",
    threshold: "1000000",
    decimals: 6,
  };

  // Compute conditionHash (canonical sorted-key JSON + SHA-256)
  const sortedKeys = Object.keys(evaluatedCondition).sort();
  const canonical = JSON.stringify(evaluatedCondition, sortedKeys);
  const hashBuf = await subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical)
  );
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
      blockNumber: 19500000,
      blockTimestamp: now.toISOString(),
      ...(overrides.resultOverrides || {}),
    },
  ];

  const attestation = {
    id: "ATST-TEST1",
    pass: true,
    results,
    passCount: 1,
    failCount: 0,
    attestedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    ...(overrides.attestationOverrides || {}),
  };

  // Sign: JSON.stringify({ id, pass, results, attestedAt })
  const sigPayload = JSON.stringify({
    id: attestation.id,
    pass: attestation.pass,
    results: attestation.results,
    attestedAt: attestation.attestedAt,
  });

  const sigBuffer = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    new TextEncoder().encode(sigPayload)
  );

  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)));

  return {
    response: { data: { attestation, sig } },
    keyPair,
  };
}

// ── Tests ──────────────────────────────────────────────────────────

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

// Test 1: Valid attestation (but with test key, so signature check will fail
// against the hardcoded InsumerAPI public key — this is expected)
console.log("\nTest 1: Signature fails for non-InsumerAPI key (expected)");
{
  const { response } = await generateTestAttestation();
  const result = await verifyAttestation(response);
  assert(!result.checks.signature.passed, "Signature should fail for test key");
  assert(result.checks.conditionHashes.passed, "Condition hashes should pass");
  assert(result.checks.freshness.passed, "Freshness should pass (no maxAge)");
  assert(result.checks.expiry.passed, "Expiry should pass");
  assert(!result.valid, "Overall should be invalid (sig failed)");
}

// Test 2: Condition hash verification
console.log("\nTest 2: Tampered conditionHash");
{
  const { response } = await generateTestAttestation({
    resultOverrides: { conditionHash: "0xdeadbeef" },
  });
  const result = await verifyAttestation(response);
  assert(
    !result.checks.conditionHashes.passed,
    "Condition hash should fail for tampered hash"
  );
  assert(
    result.checks.conditionHashes.failures?.includes(0),
    "Should report index 0 as failure"
  );
}

// Test 3: Freshness check with maxAge (5 min old: beyond maxAge plus the default 60s skew)
console.log("\nTest 3: Stale blockTimestamp with maxAge=1");
{
  const oldTimestamp = new Date(Date.now() - 300000).toISOString(); // 5 min ago
  const { response } = await generateTestAttestation({
    resultOverrides: { blockTimestamp: oldTimestamp },
  });
  const result = await verifyAttestation(response, { maxAge: 1 });
  assert(!result.checks.freshness.passed, "Freshness should fail for stale data");
}

// Test 4: Freshness passes when within maxAge
console.log("\nTest 4: Fresh blockTimestamp with maxAge=300");
{
  const { response } = await generateTestAttestation();
  const result = await verifyAttestation(response, { maxAge: 300 });
  assert(result.checks.freshness.passed, "Freshness should pass for fresh data");
}

// Test 5: Expired attestation (2 min past expiresAt: beyond the default 60s skew)
console.log("\nTest 5: Expired attestation");
{
  const pastExpiry = new Date(Date.now() - 120000).toISOString();
  const { response } = await generateTestAttestation({
    attestationOverrides: { expiresAt: pastExpiry },
  });
  const result = await verifyAttestation(response);
  assert(!result.checks.expiry.passed, "Expiry should fail for expired attestation");
}

// Test 6: Missing evaluatedCondition/conditionHash (must fail: every result carries both, spec Section 8)
console.log("\nTest 6: Results without evaluatedCondition (must fail Check 2)");
{
  const { response } = await generateTestAttestation({
    resultOverrides: {
      evaluatedCondition: undefined,
      conditionHash: undefined,
    },
  });
  // Clean up undefined values (they'd be absent in real API response)
  delete response.data.attestation.results[0].evaluatedCondition;
  delete response.data.attestation.results[0].conditionHash;
  const result = await verifyAttestation(response);
  assert(
    !result.checks.conditionHashes.passed && result.checks.conditionHashes.failures?.includes(0),
    "A result without evaluatedCondition/conditionHash fails Check 2 at its index"
  );
}

// Test 7: Invalid response shape
console.log("\nTest 7: Invalid response shape");
{
  try {
    await verifyAttestation({ foo: "bar" });
    assert(false, "Should have thrown");
  } catch (e) {
    assert(e.message.includes("missing data object"), "Should throw parse error");
  }
}

// Test 8: Freshness skips results without blockTimestamp
console.log("\nTest 8: Freshness skips results without blockTimestamp");
{
  const { response } = await generateTestAttestation({
    resultOverrides: { blockTimestamp: undefined },
  });
  delete response.data.attestation.results[0].blockTimestamp;
  const result = await verifyAttestation(response, { maxAge: 1 });
  assert(
    result.checks.freshness.passed,
    "Should pass when no blockTimestamp to check"
  );
}

// Test 9: An unresolvable kid fails closed, it does not fall back to keys[0]
console.log("\nTest 9: JWKS with no matching kid fails closed");
{
  const { response } = await generateTestAttestation();
  response.data.kid = "attacker-supplied-kid";

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => ({
      keys: [
        {
          kty: "EC",
          crv: "P-256",
          kid: "insumer-attest-v2",
          x: "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
          y: "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
        },
      ],
    }),
  });

  let result;
  try {
    result = await verifyAttestation(response, {
      jwksUrl: "https://example.invalid/.well-known/jwks.json",
    });
  } finally {
    globalThis.fetch = realFetch;
  }

  assert(result.valid === false, "Unresolvable kid must not verify");
  assert(
    result.checks.signature.passed === false,
    "Signature check must fail on an unresolvable kid"
  );
  assert(
    result.checks.signature.reason.includes("no key matching kid"),
    "Failure must name the unresolved kid, not a generic fetch error"
  );
}

// Test 10: Clock-skew allowance on expiry (default 60s, spec Section 9.4)
console.log("\nTest 10: Expiry within and beyond the clock-skew allowance");
{
  // 30s past expiresAt: inside the default allowance, so still current
  const within = await generateTestAttestation({
    attestationOverrides: { expiresAt: new Date(Date.now() - 30000).toISOString() },
  });
  let result = await verifyAttestation(within.response);
  assert(result.checks.expiry.passed, "30s past expiresAt passes under the default 60s skew");

  // the same artifact with the allowance switched off is expired
  result = await verifyAttestation(within.response, { clockSkew: 0 });
  assert(!result.checks.expiry.passed, "30s past expiresAt fails with clockSkew: 0");

  // 90s past expiresAt: beyond the default allowance
  const beyond = await generateTestAttestation({
    attestationOverrides: { expiresAt: new Date(Date.now() - 90000).toISOString() },
  });
  result = await verifyAttestation(beyond.response);
  assert(!result.checks.expiry.passed, "90s past expiresAt fails under the default 60s skew");

  // a wider caller-chosen allowance admits it
  result = await verifyAttestation(beyond.response, { clockSkew: 120 });
  assert(result.checks.expiry.passed, "90s past expiresAt passes with clockSkew: 120");
}

// Test 11: Clock-skew allowance on freshness (added to maxAge)
console.log("\nTest 11: Freshness within and beyond the clock-skew allowance");
{
  // 100s old with maxAge 60: inside maxAge + 60s skew
  const within = await generateTestAttestation({
    resultOverrides: { blockTimestamp: new Date(Date.now() - 100000).toISOString() },
  });
  let result = await verifyAttestation(within.response, { maxAge: 60 });
  assert(result.checks.freshness.passed, "100s-old block passes maxAge 60 under the default 60s skew");

  result = await verifyAttestation(within.response, { maxAge: 60, clockSkew: 0 });
  assert(!result.checks.freshness.passed, "100s-old block fails maxAge 60 with clockSkew: 0");

  // 130s old with maxAge 60: beyond maxAge + 60s skew
  const beyond = await generateTestAttestation({
    resultOverrides: { blockTimestamp: new Date(Date.now() - 130000).toISOString() },
  });
  result = await verifyAttestation(beyond.response, { maxAge: 60 });
  assert(!result.checks.freshness.passed, "130s-old block fails maxAge 60 under the default 60s skew");
  assert(
    /clock skew/.test(result.checks.freshness.reason || ""),
    "freshness reason states the allowance that was applied"
  );
}

// Test 12: The expiresAt-to-attestedAt binding keeps its own fixed grace (Check 4)
console.log("\nTest 12: Binding grace is independent of clockSkew");
{
  const now = Date.now();
  // expiresAt = attestedAt + 30 min + 30s: inside the fixed 60s binding grace
  const ok = await generateTestAttestation({
    attestationOverrides: { expiresAt: new Date(now + 30 * 60 * 1000 + 30000).toISOString() },
  });
  let result = await verifyAttestation(ok.response, { clockSkew: 0 });
  assert(result.checks.expiry.passed, "attestedAt + window + 30s passes the binding even with clockSkew: 0");

  // expiresAt = attestedAt + 30 min + 90s: beyond the binding grace, tampered
  const bad = await generateTestAttestation({
    attestationOverrides: { expiresAt: new Date(now + 30 * 60 * 1000 + 90000).toISOString() },
  });
  result = await verifyAttestation(bad.response, { clockSkew: 600 });
  assert(!result.checks.expiry.passed, "attestedAt + window + 90s fails the binding regardless of clockSkew");
  assert(
    /issuance window/.test(result.checks.expiry.reason || ""),
    "binding failure is reported as tampering, not expiry"
  );
}

// Test 16: A kid that selects no key fails the SIGNATURE verdict only. Condition hashes,
// freshness and expiry need no key and report their own results; the companion is absent when
// none was transmitted and unverifiable when one was. valid stays false throughout.
console.log("\nTest 16: Key selection failure leaves the other verdicts independent");
{
  const serve = (keys, ok = true) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => ({ ok, status: ok ? 200 : 503, statusText: ok ? "OK" : "Service Unavailable", json: async () => ({ keys }) });
    return () => { globalThis.fetch = realFetch; };
  };
  const v2Only = [{ kty: "EC", crv: "P-256", kid: "insumer-attest-v2", x: "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c", y: "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c" }];
  const opts = { jwksUrl: "https://example.invalid/.well-known/jwks.json" };

  // (a) unknown kid, key set fetched, no companion (the shape of published vector 11)
  let { response } = await generateTestAttestation();
  response.data.kid = "insumer-attest-v9";
  let restore = serve(v2Only);
  let result;
  try { result = await verifyAttestation(response, opts); } finally { restore(); }
  assert(result.valid === false, "(a) unknown kid: valid is false");
  assert(result.checks.signature.passed === false && /no key matching kid/.test(result.checks.signature.reason), "(a) unknown kid: the signature verdict carries the key-selection reason");
  assert(result.checks.conditionHashes.passed === true, "(a) unknown kid: condition hashes are recomputed and reproduce");
  assert(result.checks.freshness.passed === true && result.checks.expiry.passed === true, "(a) unknown kid: freshness and expiry report their own results");
  assert(result.checks.pq.status === "absent" && result.checks.pq.passed === true, "(a) unknown kid, no companion transmitted: pq is absent, not unverifiable");

  // (b) missing kid, key set fetched, companion transmitted (the shape of published vector 19)
  ({ response } = await generateTestAttestation());
  delete response.data.kid;
  response.data.pqSig = "AAAA";
  response.data.pqKid = "insumer-attest-pq1";
  restore = serve(v2Only);
  try { result = await verifyAttestation(response, opts); } finally { restore(); }
  assert(result.valid === false && /no kid/.test(result.checks.signature.reason), "(b) missing kid: valid is false and the signature verdict says so");
  assert(result.checks.conditionHashes.passed === true, "(b) missing kid: condition hashes are recomputed and reproduce");
  assert(result.checks.pq.status === "unverifiable" && /unknown to this verifier/.test(result.checks.pq.reason), "(b) missing kid, companion transmitted: pq is unverifiable (no preimage to rebuild), never refuted");
  assert(result.checks.pq.passed === true, "(b) ...and without a pqRequiredFrom cutoff that is reported, not refused");
  result = await (async () => { const r2 = serve(v2Only); try { return await verifyAttestation(response, { ...opts, pqRequiredFrom: "2020-01-01T00:00:00Z" }); } finally { r2(); } })();
  assert(result.checks.pq.passed === false, "(b) ...under a cutoff that has passed, the unverifiable companion fails, as on every other path");

  // (c) known kid, the key set itself unreachable: still the signature verdict's failure alone,
  // and never a fallback to the built-in key
  ({ response } = await generateTestAttestation());
  response.data.kid = "insumer-attest-v2";
  restore = serve([], false);
  try { result = await verifyAttestation(response, opts); } finally { restore(); }
  assert(result.valid === false && /JWKS fetch failed: 503/.test(result.checks.signature.reason), "(c) unreachable key set: the signature verdict names the fetch failure");
  assert(result.checks.conditionHashes.passed === true && result.checks.expiry.passed === true, "(c) unreachable key set: condition hashes and expiry still report their own results");
  assert(result.checks.pq.status === "absent", "(c) unreachable key set, no companion: pq is absent");
  response.data.pqSig = "AAAA";
  response.data.pqKid = "insumer-attest-pq1";
  restore = serve([], false);
  try { result = await verifyAttestation(response, opts); } finally { restore(); }
  assert(result.checks.pq.status === "unverifiable", "(c) unreachable key set, companion transmitted: pq is unverifiable");
}

// ── Summary ────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
