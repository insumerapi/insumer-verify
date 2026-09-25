/**
 * Post-quantum companion tests for insumer-verify (fifth verdict `pq`).
 *
 * Ephemeral keys only: a P-256 keypair for the classical signature and an ML-DSA-65 keypair
 * (from @noble/post-quantum) for the companion. fetch is stubbed to serve a JWKS carrying
 * both, with the AKP entries appended LAST as the API does.
 *
 * Proves, for BOTH signing eras (v1 bare-JSON and v2 domain-tagged canonical JSON):
 *   verified / refuted (tamper) / absent / unverifiable (unknown pqKid) statuses; that `valid`
 *   is unaffected by an absent companion until the verifier's own pqRequiredFrom date; that
 *   "evidence" mode never refuses and reports existedAtIssuance; and the JWT path with pqJwt,
 *   including the claim-binding to the ES256 JWT.
 *
 * Run: node test-pq.mjs
 */
import { verifyAttestation } from "./build/index.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const subtle = globalThis.crypto.subtle;
let passed = 0, failed = 0;
function assert(c, name) { if (c) { console.log(`  PASS: ${name}`); passed++; } else { console.log(`  FAIL: ${name}`); failed++; } }

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const b64urlBytes = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlStr = (s) => b64urlBytes(new TextEncoder().encode(s));
function canonicalize(v) { if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]"; if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}"; return JSON.stringify(v); }
async function sha256Hex(str) { const buf = await subtle.digest("SHA-256", new TextEncoder().encode(str)); return "0x" + Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join(""); }

// ── keys ──
const ec = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const ecJwk = await subtle.exportKey("jwk", ec.publicKey);
const seed = crypto.getRandomValues(new Uint8Array(32));
const pqKp = ml_dsa65.keygen(seed);
const otherPq = ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
const JWKS = { keys: [
  { kty: "EC", crv: "P-256", x: ecJwk.x, y: ecJwk.y, use: "sig", alg: "ES256", kid: "insumer-attest-v1" },
  { kty: "EC", crv: "P-256", x: ecJwk.x, y: ecJwk.y, use: "sig", alg: "ES256", kid: "insumer-attest-v2" },
  { kty: "EC", crv: "P-256", x: ecJwk.x, y: ecJwk.y, use: "sig", alg: "ES256", kid: "insumer-trust-v2" },
  // A rotation the API has already published and THIS library does not know about yet.
  // Key resolution succeeds; only the kid is unrecognised. That is the real shape of a
  // rotation, and the case the companion must call "unverifiable" rather than "refuted".
  { kty: "EC", crv: "P-256", x: ecJwk.x, y: ecJwk.y, use: "sig", alg: "ES256", kid: "insumer-attest-v3" },
  { kty: "AKP", alg: "ML-DSA-65", use: "sig", kid: "insumer-attest-pq1", pub: b64urlBytes(pqKp.publicKey) },
  { kty: "AKP", alg: "ML-DSA-65", use: "sig", kid: "insumer-trust-pq1", pub: b64urlBytes(pqKp.publicKey) },
] };
globalThis.fetch = async () => ({ ok: true, json: async () => JSON.parse(JSON.stringify(JWKS)) });
const JWKS_URL = "https://stub.test/jwks.json";

async function ecSign(str) { const der = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ec.privateKey, new TextEncoder().encode(str))); return der; }
function pqSignPreimage(domain, classicalPreimage, kp = pqKp) { return b64(ml_dsa65.sign(new TextEncoder().encode(domain + "\n" + classicalPreimage), kp.secretKey)); }

async function makeResponse(era, { withPq = true, tamperPq = false, pqKid = "insumer-attest-pq1", wrongKey = false } = {}) {
  const now = new Date();
  const ec1 = era === "v2"
    ? { type: "token_balance", chainId: 1, contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", operator: "gte", threshold: "1000" }
    : { type: "token_balance", chainId: 1, contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", operator: "gte", threshold: 1000, decimals: 6 };
  const conditionHash = era === "v2" ? await sha256Hex(canonicalize(ec1)) : await sha256Hex(JSON.stringify(ec1, Object.keys(ec1).sort()));
  const results = [{ condition: 0, met: true, evaluatedCondition: ec1, conditionHash, blockNumber: "0x1", blockTimestamp: now.toISOString() }];
  const attestation = { id: "ATST-PQ" + era, pass: true, results, passCount: 1, failCount: 0, attestedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 30 * 60 * 1000).toISOString() };
  const kid = era === "v2" ? "insumer-attest-v2" : "insumer-attest-v1";
  const classicalPreimage = era === "v2"
    ? "insumer.attestation.v2\n" + canonicalize({ v: 2, id: attestation.id, pass: attestation.pass, results, attestedAt: attestation.attestedAt })
    : JSON.stringify({ id: attestation.id, pass: attestation.pass, results, attestedAt: attestation.attestedAt });
  const sig = b64(await ecSign(classicalPreimage));
  const data = { attestation, sig, kid };
  if (withPq) {
    data.pqSig = pqSignPreimage("insumer.attestation.pq1", tamperPq ? classicalPreimage.replace('"pass":true', '"pass":false') : classicalPreimage, wrongKey ? otherPq : pqKp);
    data.pqKid = pqKid;
  }
  return { ok: true, data, meta: { version: "1.0" } };
}

for (const era of ["v1", "v2"]) {
  console.log(`\n=== raw path, ${era} key ===`);
  let r = await verifyAttestation(await makeResponse(era), { jwksUrl: JWKS_URL });
  assert(r.checks.signature.passed && r.checks.conditionHashes.passed, `${era}: classical checks pass`);
  assert(r.checks.pq.status === "verified" && r.checks.pq.passed && r.checks.pq.kid === "insumer-attest-pq1", `${era}: pq verified`);
  assert(r.valid === true, `${era}: valid`);
  assert(Object.keys(r.checks).length === 5, `${era}: five verdicts reported`);

  r = await verifyAttestation(await makeResponse(era, { tamperPq: true }), { jwksUrl: JWKS_URL });
  assert(r.checks.pq.status === "refuted" && r.valid === false && r.checks.signature.passed, `${era}: tampered companion -> refuted, valid=false, classical still passes`);

  r = await verifyAttestation(await makeResponse(era, { wrongKey: true }), { jwksUrl: JWKS_URL });
  assert(r.checks.pq.status === "refuted" && r.valid === false, `${era}: companion under the wrong key -> refuted`);

  r = await verifyAttestation(await makeResponse(era, { withPq: false }), { jwksUrl: JWKS_URL });
  assert(r.checks.pq.status === "absent" && r.checks.pq.passed && r.valid === true, `${era}: absent companion is reported and does not affect valid (no policy date)`);

  r = await verifyAttestation(await makeResponse(era, { pqKid: "insumer-attest-pq9" }), { jwksUrl: JWKS_URL });
  assert(r.checks.pq.status === "unverifiable" && /no key matching pqKid/.test(r.checks.pq.reason) && r.valid === true, `${era}: unknown pqKid -> unverifiable (could not check), not a pass and not a refute`);

  r = await verifyAttestation(await makeResponse(era, { withPq: false }), { jwksUrl: JWKS_URL, pqRequiredFrom: "2020-01-01T00:00:00Z" });
  assert(r.checks.pq.status === "absent" && r.checks.pq.passed === false && r.valid === false, `${era}: access mode past the verifier's date -> absent companion fails valid`);

  r = await verifyAttestation(await makeResponse(era, { withPq: false }), { jwksUrl: JWKS_URL, pqRequiredFrom: "2099-01-01T00:00:00Z" });
  assert(r.valid === true, `${era}: access mode before the verifier's date -> still valid`);

  r = await verifyAttestation(await makeResponse(era, { withPq: false }), { jwksUrl: JWKS_URL, mode: "evidence", pqRequiredFrom: "2020-01-01T00:00:00Z", pqActivatedAt: "2099-01-01T00:00:00Z" });
  assert(r.valid === true && r.checks.pq.status === "absent" && r.checks.pq.existedAtIssuance === false, `${era}: evidence mode never refuses; reports the companion did not exist at issuance`);

  r = await verifyAttestation(await makeResponse(era), { jwksUrl: JWKS_URL, mode: "evidence", pqActivatedAt: "2020-01-01T00:00:00Z" });
  assert(r.checks.pq.status === "verified" && r.checks.pq.existedAtIssuance === true, `${era}: evidence mode reports existedAtIssuance=true for a post-activation artifact`);

  r = await verifyAttestation(await makeResponse(era, { tamperPq: true }), { jwksUrl: JWKS_URL, mode: "evidence" });
  assert(r.checks.pq.status === "refuted" && r.valid === false, `${era}: evidence mode still fails a REFUTED companion (tamper is never excused)`);
}

console.log("\n=== JWT path with pqJwt ===");
async function makeJwt(era) {
  const now = Math.floor(Date.now() / 1000);
  const ec1 = { type: "token_balance", chainId: 1, contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", operator: "gte", threshold: "1000" };
  const conditionHash = era === "v2" ? await sha256Hex(canonicalize(ec1)) : await sha256Hex(JSON.stringify(ec1, Object.keys(ec1).sort()));
  const results = [{ condition: 0, met: true, evaluatedCondition: ec1, conditionHash, blockNumber: "0x1", blockTimestamp: new Date().toISOString() }];
  const claims = { pass: true, conditionHash: [conditionHash], results, iss: "https://api.insumermodel.com", sub: "0xabc", jti: "ATST-J" + era, iat: now, exp: now + 1800 };
  const kid = era === "v2" ? "insumer-attest-v2" : "insumer-attest-v1";
  const h = b64urlStr(JSON.stringify({ alg: "ES256", typ: "JWT", kid })), p = b64urlStr(JSON.stringify(claims));
  const jwt = `${h}.${p}.${b64urlBytes(await ecSign(`${h}.${p}`))}`;
  const ph = b64urlStr(JSON.stringify({ alg: "ML-DSA-65", typ: "JWT", kid: "insumer-attest-pq1" }));
  const pqJwt = `${ph}.${p}.${b64urlBytes(ml_dsa65.sign(new TextEncoder().encode(`${ph}.${p}`), pqKp.secretKey))}`;
  const p2 = b64urlStr(JSON.stringify({ ...claims, jti: "ATST-OTHER" }));
  const transplanted = `${ph}.${p2}.${b64urlBytes(ml_dsa65.sign(new TextEncoder().encode(`${ph}.${p2}`), pqKp.secretKey))}`;
  const signEs = async (c) => { const q = b64urlStr(JSON.stringify(c)); return `${h}.${q}.${b64urlBytes(await ecSign(`${h}.${q}`))}`; };
  const signPq = (c) => { const q = b64urlStr(JSON.stringify(c)); return `${ph}.${q}.${b64urlBytes(ml_dsa65.sign(new TextEncoder().encode(`${ph}.${q}`), pqKp.secretKey))}`; };
  return { jwt, pqJwt, transplanted, claims, signEs, signPq };
}
for (const era of ["v1", "v2"]) {
  const { jwt, pqJwt, transplanted, claims, signEs, signPq } = await makeJwt(era);
  let r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL, pqJwt });
  assert(r.valid && r.checks.pq.status === "verified", `${era} JWT string + options.pqJwt -> verified`);
  r = await verifyAttestation({ ok: true, data: { jwt, pqJwt } }, { jwksUrl: JWKS_URL });
  assert(r.valid && r.checks.pq.status === "verified", `${era} JWT-format envelope object {data.jwt, data.pqJwt} -> verified`);
  r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL });
  assert(r.valid && r.checks.pq.status === "absent", `${era} JWT without companion -> absent, still valid`);
  r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL, pqJwt: transplanted });
  assert(r.checks.pq.status === "refuted" && r.valid === false && /jti/.test(r.checks.pq.reason), `${era} companion from ANOTHER artifact (valid signature, different jti) -> refuted`);
  r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL, pqJwt: pqJwt.slice(0, -4) + "AAAA" });
  assert(r.checks.pq.status === "refuted" && r.valid === false, `${era} corrupted pqJwt signature -> refuted`);

  // The companion binds the FULL claim set. Each case below is the classical-break scenario:
  // the ES256 JWT is re-signed with the real EC key over edited claims (so its own signature
  // verifies), and the genuine pqJwt is left beside it. Every edited claim must refute.
  const clone = (c) => JSON.parse(JSON.stringify(c));
  const edits = {
    sub: (c) => { c.sub = "0x000000000000000000000000000000000000dEaD"; },
    "results[0].met": (c) => { c.results[0].met = !c.results[0].met; },
    "results[0].evaluatedCondition.threshold": (c) => { c.results[0].evaluatedCondition.threshold = "1"; },
    "conditionHash[0]": (c) => { c.conditionHash[0] = "0x" + "00".repeat(32); },
    "results[0].blockNumber": (c) => { c.results[0].blockNumber = "0x2"; },
    "results[0].blockTimestamp": (c) => { c.results[0].blockTimestamp = "2020-01-01T00:00:00.000Z"; },
    iss: (c) => { c.iss = "https://example.invalid"; },
    iat: (c) => { c.iat = c.iat - 1; },
    exp: (c) => { c.exp = c.exp + 1; },
    jti: (c) => { c.jti = "ATST-FORGED"; },
    pass: (c) => { c.pass = false; },
  };
  for (const [path, fn] of Object.entries(edits)) {
    const c = clone(claims); fn(c);
    r = await verifyAttestation(await signEs(c), { jwksUrl: JWKS_URL, pqJwt });
    assert(r.checks.signature.passed === true && r.checks.pq.status === "refuted" && r.valid === false && r.checks.pq.reason.includes(`"${path}"`),
      `${era} re-signed jwt with ${path} edited, genuine pqJwt beside it -> refuted, names the claim`);
  }
  let c = clone(claims); c.role = "admin";
  r = await verifyAttestation(await signEs(c), { jwksUrl: JWKS_URL, pqJwt });
  assert(r.checks.pq.status === "refuted" && r.checks.pq.reason.includes('"role"'), `${era} jwt carries a claim the companion does not -> refuted`);
  c = clone(claims); delete c.conditionHash;
  r = await verifyAttestation(await signEs(c), { jwksUrl: JWKS_URL, pqJwt });
  assert(r.checks.pq.status === "refuted" && r.checks.pq.reason.includes('"conditionHash"'), `${era} jwt drops a claim the companion carries -> refuted`);
  // Same claim set, different serialization: member order reversed at every level. Genuine, so verified.
  const reorder = (v) => Array.isArray(v) ? v.map(reorder) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reorder(x)])) : v;
  const reordered = signPq(reorder(claims));
  assert(reordered.split(".")[1] !== jwt.split(".")[1], `${era} (reordered companion payload is not byte-identical to the jwt payload)`);
  r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL, pqJwt: reordered });
  assert(r.valid && r.checks.pq.status === "verified", `${era} companion with the same claims in a different member order -> verified (byte identity is never required)`);
}

console.log("\n=== whole format:jwt response: the tokens beside the attestation are verified too ===");
// What the API returns for format:"jwt": attestation + sig + kid + pqSig + pqKid AND jwt + pqJwt.
async function makeWhole(era, id) {
  const resp = await makeResponse(era);
  const a = resp.data.attestation; if (id) a.id = id;
  if (id) { // re-sign the attestation under its new id so the response is genuine
    const pre = era === "v2" ? "insumer.attestation.v2\n" + canonicalize({ v: 2, id: a.id, pass: a.pass, results: a.results, attestedAt: a.attestedAt }) : JSON.stringify({ id: a.id, pass: a.pass, results: a.results, attestedAt: a.attestedAt });
    resp.data.sig = b64(await ecSign(pre)); resp.data.pqSig = pqSignPreimage("insumer.attestation.pq1", pre);
  }
  const claims = { pass: a.pass, conditionHash: a.results.map((x) => x.conditionHash), blockNumber: a.results[0].blockNumber, blockTimestamp: a.results[0].blockTimestamp, results: a.results,
    iss: "https://api.insumermodel.com", sub: "0xabc", jti: a.id, iat: Math.floor(Date.parse(a.attestedAt) / 1000), exp: Math.floor(Date.parse(a.expiresAt) / 1000) };
  const sign = async (c, kid = resp.data.kid) => { const h = b64urlStr(JSON.stringify({ alg: "ES256", typ: "JWT", kid })), q = b64urlStr(JSON.stringify(c)); return `${h}.${q}.${b64urlBytes(await ecSign(`${h}.${q}`))}`; };
  const signPq = (c) => { const h = b64urlStr(JSON.stringify({ alg: "ML-DSA-65", typ: "JWT", kid: "insumer-attest-pq1" })), q = b64urlStr(JSON.stringify(c)); return `${h}.${q}.${b64urlBytes(ml_dsa65.sign(new TextEncoder().encode(`${h}.${q}`), pqKp.secretKey))}`; };
  resp.data.jwt = await sign(claims); resp.data.pqJwt = signPq(claims);
  return { resp, claims, sign, signPq };
}
for (const era of ["v1", "v2"]) {
  const { resp, claims, sign, signPq } = await makeWhole(era);
  const clone = (o) => JSON.parse(JSON.stringify(o));
  let r = await verifyAttestation(resp, { jwksUrl: JWKS_URL });
  assert(r.valid === true && r.checks.jwt && r.checks.jwt.passed && r.checks.jwt.pq.status === "verified" && Object.keys(r.checks).length === 6, `${era} genuine whole response -> valid, checks.jwt passed, its companion verified`);
  r = await verifyAttestation(await makeResponse(era), { jwksUrl: JWKS_URL });
  assert(r.checks.jwt === undefined && r.valid, `${era} response without tokens -> no jwt verdict, as before`);

  let t = clone(resp); const [h, , sg] = t.data.jwt.split("."); t.data.jwt = [h, b64urlStr(JSON.stringify({ ...claims, sub: "0xdead" })), sg].join(".");
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === false && r.checks.signature.passed && r.checks.pq.status === "verified" && r.checks.jwt.passed === false && /signature/.test(r.checks.jwt.reason), `${era} data.jwt edited inside a genuine response -> valid=false at checks.jwt (attestation verdicts unchanged)`);

  // Same era, same key, both tokens GENUINE, but they belong to another attestation.
  const otherWhole = await makeWhole(era, "ATST-OTHER-" + era);
  t = clone(resp); t.data.jwt = otherWhole.resp.data.jwt; t.data.pqJwt = otherWhole.resp.data.pqJwt;
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === false && r.checks.jwt.passed === false && /"jti"/.test(r.checks.jwt.reason), `${era} genuine token pair from ANOTHER attestation -> refused, jti differs from the attestation`);

  for (const [name, fn] of [["pass", (c) => { c.pass = false; }], ["results[0].met", (c) => { c.results[0].met = false; }], ["exp", (c) => { c.exp += 600; }]]) {
    const c = clone(claims); fn(c); t = clone(resp); t.data.jwt = await sign(c); t.data.pqJwt = signPq(c);
    r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
    assert(r.valid === false && r.checks.jwt.passed === false && r.checks.jwt.reason.includes(`"${name}"`), `${era} validly signed token pair whose ${name} differs from the attestation -> refused`);
  }
  t = clone(resp); t.data.pqJwt = signPq({ ...claims, sub: "0xdead" });
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === false && r.checks.jwt.pq.status === "refuted", `${era} companion token whose claims differ from data.jwt -> checks.jwt.pq refuted`);
  t = clone(resp); delete t.data.pqJwt;
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === true && r.checks.jwt.pq.status === "absent", `${era} data.jwt with no companion token -> verified classically, companion absent, still valid`);
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL, pqRequiredFrom: "2020-01-01T00:00:00Z" });
  assert(r.valid === false && r.checks.jwt.passed === false, `${era} ...and past the verifier's cutoff that absence fails`);
  t = clone(resp); delete t.data.jwt;
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === false && r.checks.jwt.passed === false, `${era} data.pqJwt with no data.jwt -> refused`);
  t = clone(resp); t.data.jwt = await sign(claims, era === "v2" ? "insumer-attest-v1" : "insumer-attest-v2");
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === false && /kid/.test(r.checks.jwt.reason), `${era} data.jwt under a different kid than the response -> refused`);
  t = clone(resp); t.data.jwt = null; t.data.pqJwt = null;
  r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
  assert(r.valid === true && r.checks.jwt === undefined, `${era} jwt: null / pqJwt: null -> treated as no tokens, never a false refusal`);
  for (const bad of [123, "a.b", "x.bnVsbA.AAAA"]) {
    t = clone(resp); t.data.jwt = bad;
    r = await verifyAttestation(t, { jwksUrl: JWKS_URL });
    assert(r.valid === false && r.checks.jwt.passed === false && r.checks.signature.passed, `${era} data.jwt = ${JSON.stringify(bad)} -> a verdict, never a throw`);
  }
}
// A companion that cannot be compared with its jwt (nesting past the bound) is refuted, not unverifiable.
{
  const { jwt, claims, signPq } = await makeJwt("v2");
  let deep = 1; for (let i = 0; i < 200; i++) deep = [deep];
  const r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL, pqJwt: signPq({ ...claims, extra: deep }) });
  assert(r.checks.pq.status === "refuted" && r.valid === false, "pqJwt carrying a claim nested past the depth bound -> refuted");
  const { signEs } = await makeJwt("v2");
  const both = { ...claims, extra: deep };
  const reorderedBoth = Object.fromEntries(Object.entries(both).reverse());
  const r2 = await verifyAttestation(await signEs(both), { jwksUrl: JWKS_URL, pqJwt: signPq(reorderedBoth) });
  assert(r2.checks.pq.status === "refuted", "both tokens nested past the bound and not byte-identical -> refuted (cannot be shown equal)");
}
// A bare JWT whose payload is not an object ends in a verdict.
{
  const h = b64urlStr(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "insumer-attest-v2" }));
  const r = await verifyAttestation(`${h}.bnVsbA.AAAA`, { jwksUrl: JWKS_URL });
  assert(r.valid === false && /not a JSON object/.test(r.checks.signature.reason), "JWT string with payload literal null -> parse verdict, no throw");
}

// ── Trust profiles: the companion under the trust domain, v1 and v2 ──
console.log("\n=== trust path, v1 and v2 ===");
async function makeTrust(era, { withPq = true, tamper = false } = {}) {
  const now = new Date();
  const trust = { id: "TRST-PQ" + era, wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", conditionSetVersion: "2026-08", dimensions: { stablecoins: { checks: [], passCount: 0, failCount: 0, total: 0 } }, summary: { totalChecks: 0, totalPassed: 0, totalFailed: 0, dimensionsWithActivity: 0, dimensionsChecked: 1 }, profiledAt: now.toISOString(), expiresAt: new Date(now.getTime() + 30 * 60 * 1000).toISOString() };
  const kid = era === "v2" ? "insumer-trust-v2" : "insumer-attest-v1";
  const classical = era === "v2" ? "insumer.trust.v2\n" + canonicalize(trust) : JSON.stringify(trust);
  const sig = b64(await ecSign(classical));
  const data = { trust, sig, kid };
  if (withPq) { data.pqSig = pqSignPreimage("insumer.trust.pq1", tamper ? classical.replace('"id":', '"id" :') : classical); data.pqKid = "insumer-trust-pq1"; }
  return { ok: true, data };
}
const { verifyTrustProfile } = await import("./build/index.js");
for (const era of ["v1", "v2"]) {
  let r = await verifyTrustProfile(await makeTrust(era), { jwksUrl: JWKS_URL });
  assert(r.valid && r.checks.pq.status === "verified" && r.checks.pq.kid === "insumer-trust-pq1", `trust ${era}: valid, pq verified under insumer-trust-pq1`);
  r = await verifyTrustProfile(await makeTrust(era, { tamper: true }), { jwksUrl: JWKS_URL });
  assert(r.checks.signature.passed && r.checks.pq.status === "refuted" && !r.valid, `trust ${era}: tampered companion -> refuted, valid=false`);
  r = await verifyTrustProfile(await makeTrust(era, { withPq: false }), { jwksUrl: JWKS_URL });
  assert(r.valid && r.checks.pq.status === "absent", `trust ${era}: absent -> reported, still valid`);
  r = await verifyTrustProfile(await makeTrust(era, { withPq: false }), { jwksUrl: JWKS_URL, pqRequiredFrom: "2020-01-01" });
  assert(!r.valid && r.checks.pq.status === "absent", `trust ${era}: absent past the verifier's cutoff -> valid=false`);
}
// ---------------------------------------------------------------------------
// Regression: a signing kid this library has not met is a ROTATION, not a forgery.
//
// The companion signs the exact classical preimage the classical kid selects. Before 1.8.9
// an unrecognised kid fell through to the v1 preimage builder, the ML-DSA check ran against
// bytes the issuer never signed, and a genuine untouched companion came back "refuted" — the
// strongest word available, and one the spec says MUST fail the artifact. The first new
// signing kid would have had every deployed copy accusing honest artifacts of tampering.
// Key rotations are two-sided; the verifier half is this.
// ---------------------------------------------------------------------------
console.log("\n=== unknown classical kid: rotation tolerance ===");
{
  const future = await makeResponse("v2");
  future.data.kid = "insumer-attest-v3";            // companion untouched and genuine
  let r = await verifyAttestation(future, { jwksUrl: JWKS_URL });
  assert(r.checks.pq.status === "unverifiable",
    'unknown classical kid -> pq unverifiable, never refuted');
  assert(!r.checks.signature.passed,
    'unknown classical kid -> the classical signature still fails (artifact refused)');
  assert(/unknown to this verifier/.test(r.checks.pq.reason ?? ""),
    'unknown classical kid -> the reason says the preimage cannot be reconstructed');

  // A KNOWN kid naming the wrong artifact type is a relabelled artifact, not a rotation.
  // It keeps its long-published "refuted" verdict (vector 21-trust-under-attest-kid).
  const relabelled = await makeResponse("v2");
  relabelled.data.kid = "insumer-trust-v2";
  r = await verifyAttestation(relabelled, { jwksUrl: JWKS_URL });
  assert(r.checks.pq.status === "refuted",
    'known kid naming the wrong artifact type -> still refuted, not softened to unverifiable');
}

// Regression: "absent" must name the CALL, not the artifact, on the bare-token path.
// A caller that forgets options.pqJwt otherwise sees a clean "absent" that a pqRequiredFrom
// policy turns into a refusal of a genuine attestation.
console.log("\n=== absent names the call, not the artifact ===");
{
  const { jwt, pqJwt } = await makeJwt("v2");
  let r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL });          // companion omitted
  assert(r.checks.pq.status === "absent", 'bare token without options.pqJwt -> absent');
  assert(/supplied to this call/.test(r.checks.pq.reason ?? ""),
    'bare token without options.pqJwt -> the reason names the call, not the artifact');
  r = await verifyAttestation(jwt, { jwksUrl: JWKS_URL, pqJwt });       // companion supplied
  assert(r.checks.pq.status === "verified",
    'the same token WITH options.pqJwt -> verified (the artifact was never the problem)');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
