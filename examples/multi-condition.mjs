/**
 * multi-condition.mjs — Multiple conditions across different chains.
 *
 * A single attestation request can check up to 10 conditions across any
 * combination of the 37 supported chains. The response is one signed
 * attestation covering all conditions — pass is true only if ALL are met.
 *
 * Usage: INSUMER_API_KEY=insr_live_... node examples/multi-condition.mjs
 */

import { verifyAttestation } from "insumer-verify";

const API_KEY = process.env.INSUMER_API_KEY;
if (!API_KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// Check multiple conditions in a single call:
// - USDC on Ethereum (EVM, chainId 1)
// - UNI governance token on Ethereum
// - USDC on Base (EVM, chainId 8453)
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
        threshold: "100",
        label: "USDC >= 100 on Ethereum",
      },
      {
        type: "token_balance",
        chainId: 1,
        contractAddress: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
        threshold: "1",
        label: "UNI >= 1 on Ethereum",
      },
      {
        type: "token_balance",
        chainId: 8453,
        contractAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        threshold: "50",
        label: "USDC >= 50 on Base",
      },
    ],
  }),
});

const apiResponse = await res.json();

if (!apiResponse.ok) {
  console.error("API error:", apiResponse.error);
  process.exit(1);
}

// Verify once — covers all conditions in the attestation
const result = await verifyAttestation(apiResponse, { maxAge: 120 });

console.log("Verification:", result.valid ? "PASSED" : "FAILED");

const { attestation } = apiResponse.data;
console.log(`\nAttestation ${attestation.id}:`);
console.log(`  Overall: ${attestation.pass ? "ALL MET" : "NOT ALL MET"} (${attestation.passCount} passed, ${attestation.failCount} failed)`);
console.log(`  Expires: ${attestation.expiresAt}`);

for (const r of attestation.results) {
  console.log(`  [${r.met ? "PASS" : "FAIL"}] ${r.label} (chain ${r.chainId}, block ${r.blockNumber})`);
}
