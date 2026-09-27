// Offline verification against a saved key set (the `jwks` option).
//
// Real, byte-exact issuer responses (copied from the public insumer-examples vectors 12, 13, 14
// and 18) are verified against keys/jwks.json with the network disabled: global fetch throws.
// Proves a record-keeper who kept a copy of the JWKS can verify both the ECDSA signature and the
// ML-DSA-65 companion without contacting anyone.
import { readFileSync } from "node:fs";
import { verifyAttestation, verifyTrustProfile } from "./build/index.js";

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log("  PASS: " + name); }
  else { fail++; console.log("  FAIL: " + name + (detail ? " :: " + detail : "")); }
}

const load = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const savedJwks = load("./keys/jwks.json");

let fetchCalls = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = async () => { fetchCalls++; throw new Error("network disabled in this test"); };

const vectors = [
  ["12-pq-companion-v2", false],
  ["13-pq-companion-v1", false],
  ["14-pq-companion-tampered", false],
  ["18-trust-profile-not-evaluated", true],
];

console.log("\n=== saved key set, network disabled: verdicts match the published expectations ===");
for (const [name, isTrust] of vectors) {
  const v = load(`./test-fixtures/offline/${name}.json`);
  const opts = { ...(v.options ?? {}), jwks: savedJwks };
  delete opts.jwksUrl;
  const out = isTrust ? await verifyTrustProfile(v.response, opts) : await verifyAttestation(v.response, opts);
  const exp = v.expected;
  for (const [k, want] of Object.entries(exp.checks)) {
    check(`${name}: checks.${k} === ${want}`, out.checks?.[k]?.passed === want, out.checks?.[k]?.reason);
  }
  if (exp.pq?.status) check(`${name}: pq status ${exp.pq.status}`, out.checks?.pq?.status === exp.pq.status, out.checks?.pq?.reason);
}

console.log("\n=== the supplied set takes precedence over jwksUrl ===");
{
  const v = load("./test-fixtures/offline/12-pq-companion-v2.json");
  const out = await verifyAttestation(v.response, { jwksUrl: "https://example.invalid/jwks.json", jwks: savedJwks });
  check("signature verifies from the supplied set even with an unreachable jwksUrl", out.checks.signature.passed === true, out.checks.signature.reason);
  check("companion verifies from the supplied set", out.checks.pq.status === "verified", out.checks.pq.reason);
}

console.log("\n=== a supplied set is honoured exactly: missing keys are not fetched ===");
{
  const v = load("./test-fixtures/offline/12-pq-companion-v2.json");
  const noPq = { keys: savedJwks.keys.filter((k) => k.kty !== "AKP") };
  const out1 = await verifyAttestation(v.response, { jwks: noPq });
  check("set without the PQ key: signature still verifies", out1.checks.signature.passed === true, out1.checks.signature.reason);
  check("set without the PQ key: companion is unverifiable, not refuted", out1.checks.pq.status === "unverifiable", out1.checks.pq.status);
  const noEc = { keys: savedJwks.keys.filter((k) => k.kty !== "EC") };
  const out2 = await verifyAttestation(v.response, { jwks: noEc });
  check("set without the classical key: signature fails", out2.checks.signature.passed === false);
  const out3 = await verifyAttestation(v.response, { jwks: {} });
  check("malformed set (no keys array): fails, does not fall back to fetching", out3.checks.signature.passed === false);
}

console.log("\n=== a key the supplied set does not hold fails the signature verdict alone ===");
{
  // A REAL issuer response whose kid the built-in key would verify. With a supplied set that
  // lacks that kid, the signature must fail (never a fallback to the built-in key), while the
  // checks that need no key report their own results: the condition hashes reproduce, and the
  // companion, whose AKP key is still in the set and whose classical kid is known, verifies.
  const v = load("./test-fixtures/offline/12-pq-companion-v2.json");
  const noV2 = { keys: savedJwks.keys.filter((k) => k.kid !== "insumer-attest-v2") };
  const out = await verifyAttestation(v.response, { jwks: noV2, mode: "evidence" });
  check("signature fails with the key-selection reason, not against the built-in key", out.checks.signature.passed === false && /no key matching kid/.test(out.checks.signature.reason ?? ""), out.checks.signature.reason);
  check("condition hashes are still recomputed and reproduce", out.checks.conditionHashes.passed === true, out.checks.conditionHashes.reason);
  check("the companion is still checked on its own and verifies", out.checks.pq.status === "verified", out.checks.pq.reason);
  check("valid is false", out.valid === false);
}

check("nothing was fetched in any case above", fetchCalls === 0, `fetch called ${fetchCalls} times`);

globalThis.fetch = realFetch;
console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
