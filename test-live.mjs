/**
 * Integration test: verifies a real InsumerAPI attestation.
 *
 * Usage: INSUMER_API_KEY=insr_live_... node test-live.mjs
 */

import { verifyAttestation } from "./build/index.js";

const apiKey = process.env.INSUMER_API_KEY;
if (!apiKey) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// USDC on Ethereum. The verdict can be true or false; verification is what this test checks.
const body = {
  wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  conditions: [
    {
      type: "token_balance",
      chainId: 1,
      contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      threshold: "1",
    },
  ],
};

console.log("Calling InsumerAPI /v1/attest...");
const res = await fetch("https://api.insumermodel.com/v1/attest", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": apiKey,
  },
  body: JSON.stringify(body),
});

const apiResponse = await res.json();
console.log("API response:", JSON.stringify(apiResponse, null, 2));

console.log("\nVerifying attestation...");
const result = await verifyAttestation(apiResponse);
console.log("Verification result:", JSON.stringify(result, null, 2));

if (result.valid) {
  console.log("\nAll checks passed.");
} else {
  console.log("\nSome checks failed:");
  for (const [name, check] of Object.entries(result.checks)) {
    if (!check.passed) console.log(`  - ${name}: ${check.reason}`);
  }
}

// Tight freshness policy: maxAge 1 s with no clock-skew allowance (the default
// allowance is 60 s, spec 9.4, and is added to maxAge). A block is usually a few
// seconds old by the time the response arrives, so this normally FAILS freshness.
// It can still pass if the anchored block was produced within the last second.
console.log("\nTesting with maxAge=1, clockSkew=0 (normally fails freshness)...");
const staleResult = await verifyAttestation(apiResponse, { maxAge: 1, clockSkew: 0 });
console.log(
  "Freshness check:",
  staleResult.checks.freshness.passed ? "PASSED" : "FAILED",
  staleResult.checks.freshness.reason || ""
);
