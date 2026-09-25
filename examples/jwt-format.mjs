/**
 * jwt-format.mjs — Request attestation as a JWT for gateway integration.
 *
 * Adding "format": "jwt" to the request returns a standard ES256 JWT
 * alongside the raw attestation. A standard JWT library or gateway can check
 * the ES256 signature and exp against the JWKS. That alone is not an access
 * decision: the gateway (or the service behind it) must also require
 * pass: true, compare each conditionHash with the one the route requires,
 * match sub to a wallet the user proved control of, and refuse a jti it has
 * seen. See "What `valid` does not tell you" in the README.
 *
 * This is the bridge between InsumerAPI and existing auth infrastructure:
 * the attestation format is standard, so it plugs into standard tools.
 *
 * Usage: INSUMER_API_KEY=insr_live_... node examples/jwt-format.mjs
 */

import { verifyAttestation } from "insumer-verify";

const API_KEY = process.env.INSUMER_API_KEY;
if (!API_KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// Request JWT format
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
    ],
    format: "jwt",
  }),
});

const apiResponse = await res.json();

if (!apiResponse.ok) {
  console.error("API error:", apiResponse.error);
  process.exit(1);
}

// The JWT is in the response data
const jwt = apiResponse.data.jwt;
console.log("JWT token:", jwt);
console.log();

// Decode and inspect JWT claims (without verification, for display)
const [, payloadB64] = jwt.split(".");
const claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
console.log("JWT claims:");
console.log(`  iss: ${claims.iss}`);
console.log(`  sub: ${claims.sub} (wallet)`);
console.log(`  jti: ${claims.jti} (attestation ID)`);
console.log(`  pass: ${claims.pass}`);
console.log(`  iat: ${new Date(claims.iat * 1000).toISOString()}`);
console.log(`  exp: ${new Date(claims.exp * 1000).toISOString()}`);
console.log();

// Verify the JWT — insumer-verify auto-detects string input as JWT.
// Pass pqJwt too: a bare token string cannot carry its post-quantum companion, and without
// it the companion is reported "absent" — which a pqRequiredFrom policy refuses, on an
// attestation whose companion would have verified.
const result = await verifyAttestation(jwt, { pqJwt: apiResponse.data.pqJwt });

console.log("JWT verification:", result.valid ? "PASSED" : "FAILED");
console.log("Checks:", JSON.stringify(result.checks, null, 2));

// You can also verify the raw attestation from the same response
const rawResult = await verifyAttestation(apiResponse);
console.log("\nRaw attestation verification:", rawResult.valid ? "PASSED" : "FAILED");
