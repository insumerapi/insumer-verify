/**
 * basic-attest.mjs — Single token balance attestation + verification.
 *
 * Demonstrates the core flow:
 * 1. Send conditions to InsumerAPI
 * 2. Receive a signed attestation (boolean, not balance)
 * 3. Verify it cryptographically, with no call back to the API
 *
 * Usage: INSUMER_API_KEY=insr_live_... node examples/basic-attest.mjs
 */

import { verifyAttestation } from "insumer-verify";

const API_KEY = process.env.INSUMER_API_KEY;
if (!API_KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// 1. Request an attestation — "does this wallet hold >= 1000 USDC on Ethereum?"
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
        threshold: "1000",
        label: "USDC >= 1000 on Ethereum",
      },
    ],
  }),
});

const apiResponse = await res.json();

// Check for RPC failure (retryable, not a verification failure)
if (!apiResponse.ok && apiResponse.error?.code === "rpc_failure") {
  console.log("RPC failure — retry after 2-5 seconds:", apiResponse.error.failedConditions);
  process.exit(1);
}

// 2. Verify the attestation — signature, condition hashes, freshness, expiry
const result = await verifyAttestation(apiResponse, {
  maxAge: 120, // reject if block data is older than 2 minutes
});

console.log("Verification:", result.valid ? "PASSED" : "FAILED");
console.log("Checks:", JSON.stringify(result.checks, null, 2));

if (result.valid) {
  const { pass, results } = apiResponse.data.attestation;
  console.log(`\nAttestation: ${pass ? "ALL MET" : "NOT ALL MET"}`);
  for (const r of results) {
    console.log(`  ${r.label}: ${r.met ? "met" : "not met"} (block ${r.blockNumber})`);
  }
}
