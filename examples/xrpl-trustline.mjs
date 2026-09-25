/**
 * xrpl-trustline.mjs — XRPL trust line token attestation.
 *
 * XRPL uses a different addressing model than EVM chains:
 * - Tokens are identified by issuer address + currency code
 * - The contractAddress field holds the issuer's r-address
 * - Results include ledgerIndex/ledgerHash instead of blockNumber/blockTimestamp
 * - Trust line tokens include trustLineState with frozen status
 *
 * The attestation format is the same — signed, verifiable, boolean.
 * The chain-specific details are in the evaluatedCondition and result fields.
 *
 * Usage: INSUMER_API_KEY=insr_live_... node examples/xrpl-trustline.mjs
 */

import { verifyAttestation } from "insumer-verify";

const API_KEY = process.env.INSUMER_API_KEY;
if (!API_KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// XRPL token issuers and currency codes
const RLUSD_ISSUER = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";
const RLUSD_CURRENCY = "524C555344000000000000000000000000000000";

const USDC_ISSUER = "rGm7WCVp9gb4jZHWTEtGUr4dd74z2XuWhE";
const USDC_CURRENCY = "5553444300000000000000000000000000000000";

// Check RLUSD and USDC on XRPL
// Note: XRPL uses xrplWallet parameter (not wallet, which is EVM)
const res = await fetch("https://api.insumermodel.com/v1/attest", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  },
  body: JSON.stringify({
    xrplWallet: "ra8xqX4QhcogFfxpMxMByvFnXyxw9E8rzY",
    conditions: [
      {
        type: "token_balance",
        chainId: "xrpl",
        contractAddress: RLUSD_ISSUER,
        currency: RLUSD_CURRENCY,
        threshold: "10",
        label: "RLUSD >= 10 on XRPL",
      },
      {
        type: "token_balance",
        chainId: "xrpl",
        contractAddress: USDC_ISSUER,
        currency: USDC_CURRENCY,
        threshold: "5",
        label: "USDC >= 5 on XRPL",
      },
    ],
  }),
});

const apiResponse = await res.json();

if (!apiResponse.ok) {
  console.error("API error:", apiResponse.error);
  process.exit(1);
}

// Verify — same function, same checks. XRPL results use ledgerIndex
// instead of blockTimestamp, so freshness check skips them gracefully.
const result = await verifyAttestation(apiResponse, { maxAge: 120 });

console.log("Verification:", result.valid ? "PASSED" : "FAILED");

const { attestation } = apiResponse.data;
console.log(`\nAttestation ${attestation.id}:`);

for (const r of attestation.results) {
  console.log(`\n  ${r.label}: ${r.met ? "MET" : "NOT MET"}`);
  console.log(`    Chain: ${r.chainId}`);

  // XRPL-specific fields
  if (r.ledgerIndex) {
    console.log(`    Ledger index: ${r.ledgerIndex}`);
  }
  if (r.ledgerHash) {
    console.log(`    Ledger hash: ${r.ledgerHash}`);
  }

  // Trust line state (non-native tokens only)
  if (r.trustLineState) {
    console.log(`    Trust line frozen: ${r.trustLineState.frozen}`);
  }

  // The evaluatedCondition uses contractAddress for the issuer
  console.log(`    Issuer (contractAddress): ${r.evaluatedCondition.contractAddress}`);
  console.log(`    Currency: ${r.evaluatedCondition.currency}`);
}
