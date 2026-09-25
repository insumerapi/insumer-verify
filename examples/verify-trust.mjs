/**
 * verify-trust.mjs: Trust profile request + verification.
 *
 * A trust profile is not a score and not an opinion. It is cryptographically
 * verifiable evidence organized by dimension, signed as a whole, so any
 * relying party can check it independently.
 *
 * Demonstrates the flow:
 * 1. Request a trust profile from InsumerAPI
 * 2. Receive the signed profile ({ trust, sig, kid })
 * 3. Verify it with verifyTrustProfile (JWKS key distribution)
 * 4. Batch: verify each entry of /v1/trust/batch individually
 *
 * Usage: INSUMER_API_KEY=insr_live_... node examples/verify-trust.mjs
 */

import { verifyTrustProfile } from "insumer-verify";

const API_KEY = process.env.INSUMER_API_KEY;
if (!API_KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

const JWKS_URL = "https://insumermodel.com/.well-known/jwks.json";

// 1. Request a trust profile for a wallet
const res = await fetch("https://api.insumermodel.com/v1/trust", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  },
  body: JSON.stringify({
    wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  }),
});

const apiResponse = await res.json();

if (!apiResponse.ok) {
  console.error("API error:", JSON.stringify(apiResponse.error || apiResponse));
  process.exit(1);
}

// 2. Verify the profile: signature (ECDSA P-256, key selected by kid from the
//    JWKS), freshness (optional, via maxAge), and expiry
const result = await verifyTrustProfile(apiResponse, {
  jwksUrl: JWKS_URL,
  maxAge: 3600, // optional: reject profiles (or on-chain reads) older than 1 hour
});

console.log("Verification:", result.valid ? "PASSED" : "FAILED");
console.log("Checks:", JSON.stringify(result.checks, null, 2));

// 3. Render only the verified profile (result.trust), gated on result.valid.
//    Never render your own copy of the response: result.trust is the exact
//    object whose signature was checked.
if (result.valid) {
  const t = result.trust;
  console.log(`\nTrust profile for ${t.wallet}`);
  console.log(`Profiled at ${t.profiledAt}, expires ${t.expiresAt}`);
  console.log(`Dimensions: ${Object.keys(t.dimensions).join(", ")}`);
  console.log("Summary:", JSON.stringify(t.summary, null, 2));
}

// 4. Batch path: one signed profile per wallet, verified one at a time.
//    A batch is never verified as a whole.
const batchRes = await fetch("https://api.insumermodel.com/v1/trust/batch", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  },
  body: JSON.stringify({
    wallets: [
      { wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" },
      { wallet: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B" },
    ],
  }),
});

const batch = await batchRes.json();

if (batch.ok) {
  console.log("\nBatch verification:");
  for (const entry of batch.data.results) {
    if (entry.error) {
      console.log(`  error: ${entry.error}`);
      continue;
    }
    const entryResult = await verifyTrustProfile(entry, { jwksUrl: JWKS_URL });
    console.log(`  ${entryResult.trust?.wallet}: ${entryResult.valid ? "PASSED" : "FAILED"}`);
  }
}
