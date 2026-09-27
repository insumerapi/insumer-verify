// Depth-bound regression suite.
//
// Canonicalization runs alongside signature verification, not after it, so the
// recursive walk is reachable by anyone holding an artifact. Unbounded, a deeply
// nested artifact exhausted the call stack; worse, Promise.all left its siblings
// running and their rejections landed as UNHANDLED rejections, which Node >=15
// turns into a process exit that the caller's own try/catch cannot prevent.
//
// Deliberately NO process-level handlers here: if an orphan rejection ever comes
// back, this suite must die rather than quietly pass.
import { verifyAttestation, verifyTrustProfile, MAX_CANONICAL_DEPTH } from "./build/index.js";

let pass = 0, fail = 0;
const ok  = (c, m) => { if (c) { pass++; console.log(`  PASS: ${m}`); } else { fail++; console.log(`  FAIL: ${m}`); } };

const nestObj = n => { let o = { leaf: 1 }; for (let i = 0; i < n; i++) o = { a: o }; return o; };
const nestArr = n => { let a = [1];        for (let i = 0; i < n; i++) a = [a];       return a; };

const art = (v, kid) => ({ ok: true, data: { kid, sig: "0x" + "ab".repeat(64), attestation: {
  id: "depth-probe", pass: true,
  attestedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 3600e3).toISOString(),
  results: [{ conditionHash: "0x" + "00".repeat(32), evaluatedCondition: v }] } } });

const b64u = s => Buffer.from(s, "utf8").toString("base64url");
// Built as TEXT: JSON.stringify on a deep object overflows the HARNESS itself.
const deepText = n => '{"a":'.repeat(n) + "1" + "}".repeat(n);
const jwtArt = depth => [
  b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "insumer-attest-v2" })),
  b64u('{"id":"x","pass":true,"attestedAt":"' + new Date().toISOString() +
       '","expiresAt":"' + new Date(Date.now() + 3600e3).toISOString() +
       '","results":[{"conditionHash":"0x' + "00".repeat(32) +
       '","evaluatedCondition":' + deepText(depth) + "}]}"),
  Buffer.alloc(64).toString("base64url"),
].join(".");

const refused = r => /too deeply nested/i.test(
  String(r?.checks?.conditionHashes?.reason ?? "") + String(r?.checks?.signature?.reason ?? "") + String(r?.checks?.pq?.reason ?? ""));

console.log(`\nTest 1: the bound is stated and exported (= ${MAX_CANONICAL_DEPTH})`);
ok(MAX_CANONICAL_DEPTH === 128, "MAX_CANONICAL_DEPTH is 128, matching A2A #2246 / in-toto #570");

console.log("\nTest 2: a hostile artifact yields a VERDICT, never a throw");
for (const kid of ["insumer-attest-v2", "insumer-attest-v1"]) {
  let threw = false, r;
  try { r = await verifyAttestation(art(nestObj(50000), kid)); } catch { threw = true; }
  ok(!threw, `${kid}: 50,000-deep object returns instead of throwing`);
  ok(!threw && r.valid === false, `${kid}: and the verdict is invalid`);
  ok(!threw && refused(r), `${kid}: and the reason names the depth refusal`);
}

console.log("\nTest 3: deep ARRAYS are bounded too (the .map index trap)");
// `value.map(canonicalize)` would hand the array INDEX in as the depth and
// silently defeat the bound; the recursive calls must pass depth explicitly.
let threwArr = false, rArr;
try { rArr = await verifyAttestation(art(nestArr(50000), "insumer-attest-v2")); } catch { threwArr = true; }
ok(!threwArr && rArr.valid === false && refused(rArr), "50,000-deep array is refused, not accepted");

console.log("\nTest 4: the JWT path is bounded on the same rule");
let threwJwt = false, rJwt;
try { rJwt = await verifyAttestation(jwtArt(50000)); } catch { threwJwt = true; }
ok(!threwJwt && rJwt.valid === false && refused(rJwt), "50,000-deep JWT payload is refused, not a throw");

console.log("\nTest 5: two-sided — normal depth is untouched");
let threwOk = false, rOk;
try { rOk = await verifyAttestation(art(nestObj(120), "insumer-attest-v2")); } catch { threwOk = true; }
ok(!threwOk, "depth 120 (inside the bound) still verifies normally");
ok(!threwOk && !refused(rOk), "depth 120 is NOT refused as too deep");
// The deepest artifact in the published conformance corpus nests 9 levels.
let threwReal = false;
try { await verifyAttestation(art(nestObj(9), "insumer-attest-v2")); } catch { threwReal = true; }
ok(!threwReal, "depth 9 (the deepest real published vector) is unaffected");

console.log("\nTest 6: trust profiles return a verdict on a hostile profile");
let threwT = false;
try { await verifyTrustProfile({ ok: true, data: { kid: "insumer-trust-v2", sig: Buffer.alloc(64).toString("base64"),
  trust: { wallet: "0x" + "ab".repeat(20), profiledAt: new Date().toISOString(),
           summary: { s: 1 }, dimensions: nestObj(50000) } } }); } catch { threwT = true; }
ok(!threwT, "50,000-deep trust profile returns instead of throwing");

console.log("\nTest 6b: a WELL-FORMED trust profile nested past the bound returns a verdict, companion or not");
{
  const deepTrust = (withPq) => ({ ok: true, data: { kid: "insumer-trust-v2", sig: Buffer.alloc(64).toString("base64"),
    ...(withPq ? { pqSig: "AAAA", pqKid: "insumer-trust-pq1" } : {}),
    trust: { id: "t", wallet: "0x" + "ab".repeat(20), conditionSetVersion: "v2", dimensions: { deep: nestObj(200) },
             summary: { s: 1 }, profiledAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600e3).toISOString() } } });
  let threw = false, r;
  try { r = await verifyTrustProfile(deepTrust(false)); } catch { threw = true; }
  ok(!threw && r?.checks?.pq?.status === "absent" && r.checks.pq.passed === true, "no companion transmitted: returns, pq is absent (never canonicalized on the companion's behalf)");
  ok(r?.valid === false && /nests deeper|too deeply nested/i.test(r?.checks?.signature?.reason ?? ""), "...and the profile is still refused at the signature");
  threw = false;
  try { r = await verifyTrustProfile(deepTrust(true)); } catch { threw = true; }
  ok(!threw && r?.checks?.pq?.status === "unverifiable" && /too deeply nested/i.test(r.checks.pq.reason ?? ""), "companion transmitted: returns, pq is unverifiable with the depth refusal, not a thrown call");
}

console.log("\nTest 6c: an attestation nested past the bound with NO companion reports the companion absent");
{
  const r = await verifyAttestation(art(nestObj(200), "insumer-attest-v2"));
  ok(r.valid === false && refused(r), "the artifact is refused");
  ok(r.checks.pq.status === "absent" && r.checks.pq.passed === true, "pq is absent (no companion was transmitted), not unverifiable");
  const withPq = art(nestObj(200), "insumer-attest-v2"); withPq.data.pqSig = "AAAA"; withPq.data.pqKid = "insumer-attest-pq1";
  const r2 = await verifyAttestation(withPq);
  ok(r2.checks.pq.status === "unverifiable" && /too deeply nested/i.test(r2.checks.pq.reason ?? ""), "with a companion transmitted, pq is unverifiable with the depth refusal");
}

// An orphaned rejection surfaces a tick later; give it room to kill us if it can.
await new Promise(r => setTimeout(r, 500));
console.log("\nTest 7: no orphaned rejection took the process down");
ok(true, "process survived past the microtask queue with no unhandledRejection handler");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
