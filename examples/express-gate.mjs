/**
 * express-gate.mjs: gate an Express route on an InsumerAPI attestation.
 *
 * A valid signature proves InsumerAPI issued the artifact unmodified. It does not
 * say which conditions were asked, which wallet was read, or whether the same
 * artifact was already used. The server has to decide those, so this example:
 *
 *   - fixes the required conditions in server code (never taken from the client);
 *   - uses only a wallet the user has proved control of (your sign-in decides that);
 *   - checks `pass` and compares every evaluated condition with the required ones.
 *
 * Two routes show the two safe patterns:
 *
 *   POST /api/premium       (preferred, simplest) the server calls /v1/attest itself
 *                           for the session's proven wallet, then verifies the answer.
 *   POST /api/premium-jwt   the client sends a `format: "jwt"` token it obtained. The
 *                           server also checks `sub` against the proven wallet and
 *                           accepts each token id (`jti`) once until it expires.
 *
 * Usage:  INSUMER_API_KEY=insr_live_... DEMO_WALLET=0x... node examples/express-gate.mjs
 * Then:   curl -X POST http://localhost:3000/api/premium
 *         curl -X POST http://localhost:3000/api/premium-jwt \
 *              -H "Content-Type: application/json" -d '{"token": "<jwt>"}'
 *
 * Requires express, which is not a dependency of this package:
 *   npm install express insumer-verify
 */

import express from "express";
import { verifyAttestation, DEFAULT_CLOCK_SKEW_SECONDS } from "insumer-verify";

const API_KEY = process.env.INSUMER_API_KEY;
const JWKS_URL = "https://insumermodel.com/.well-known/jwks.json";

// The conditions this route requires. Server-side constant: a client that could
// choose them could ask for something trivially true.
const REQUIRED_CONDITIONS = [
  {
    type: "token_balance",
    chainId: 1,
    contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC on Ethereum
    threshold: "1000",
    label: "USDC >= 1000 on Ethereum", // for display only; labels are caller-written
  },
];

// Replace with your own sign-in. The wallet must be one the user PROVED control of
// (for example by signing a one-time challenge), never one the request names.
// For this demo it is fixed by the DEMO_WALLET environment variable.
function provenWallet(req) {
  // Fail closed: the fixed demo wallet is never used in production.
  if (process.env.NODE_ENV === "production") return null;
  return process.env.DEMO_WALLET || null;
}

// Compare what was evaluated with what the route requires. `label` is never compared:
// the caller writes it. verifyAttestation has already checked that each conditionHash
// matches its evaluatedCondition, so comparing evaluatedCondition pins the hash too.
function conditionsMatch(results) {
  if (!Array.isArray(results) || results.length !== REQUIRED_CONDITIONS.length) return false;
  return REQUIRED_CONDITIONS.every((want, i) => {
    const got = results[i]?.evaluatedCondition;
    return (
      got &&
      got.type === want.type &&
      got.chainId === want.chainId &&
      String(got.contractAddress).toLowerCase() === want.contractAddress.toLowerCase() &&
      String(got.threshold) === want.threshold // v2 echoes "1000"; a v1 key echoes 1000
    );
  });
}

// Cached key set: without `jwks`, the JWT path fetches the JWKS on every call.
// Refreshed hourly so a newly published key is picked up (keys are never removed).
let jwksCache = null;
let jwksFetchedAt = 0;
async function getJwks() {
  if (!jwksCache || Date.now() - jwksFetchedAt > 3600_000) {
    const res = await fetch(JWKS_URL);
    if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
    jwksCache = await res.json();
    jwksFetchedAt = Date.now();
  }
  return jwksCache;
}

const app = express();
app.use(express.json());

// Pattern 1 (preferred): the server asks InsumerAPI directly. The server picks the
// wallet and the conditions, and the answer comes straight from the API, so there is
// nothing for a client to substitute or replay.
app.post("/api/premium", async (req, res) => {
  const wallet = provenWallet(req);
  if (!wallet) return res.status(401).json({ error: "Sign in with your wallet first" });

  try {
    const apiRes = await fetch("https://api.insumermodel.com/v1/attest", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
      body: JSON.stringify({ wallet, conditions: REQUIRED_CONDITIONS }),
    });
    const response = await apiRes.json();
    if (!response.ok) {
      // rpc_failure is retryable and is not a "no"; see the README.
      if (response.error?.code === "rpc_failure") return res.status(503).json({ error: "Could not check conditions, try again" });
      return res.status(502).json({ error: "Attestation request refused" });
    }

    const result = await verifyAttestation(response, { jwks: await getJwks(), maxAge: 120 });
    if (!result.valid) return res.status(403).json({ error: "Verification failed", checks: result.checks });

    const { id, pass, results } = response.data.attestation;
    if (!conditionsMatch(results)) return res.status(403).json({ error: "Unexpected conditions" });
    if (pass !== true) return res.status(403).json({ error: "Conditions not met", attestationId: id });

    res.json({ message: "Welcome", attestationId: id });
  } catch (err) {
    res.status(502).json({ error: "Attestation request failed" });
  }
});

// Pattern 2: the client sends a token. Accept format "jwt" only: the raw format
// signs no wallet for most condition types, so it cannot show whose wallet was read.
// In production keep this in a store shared by every server instance.
const seenJti = new Map(); // jti -> exp (seconds). Kept until the token expires.

app.post("/api/premium-jwt", async (req, res) => {
  const wallet = provenWallet(req);
  if (!wallet) return res.status(401).json({ error: "Sign in with your wallet first" });

  const token = req.body?.token;
  if (typeof token !== "string") return res.status(400).json({ error: "Send { token: <jwt> }" });

  try {
    const result = await verifyAttestation(token, { jwks: await getJwks(), maxAge: 120 });
    if (!result.valid) return res.status(403).json({ error: "Verification failed", checks: result.checks });

    // Signature verified above, so the claims can be read.
    const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());

    // Bind the wallet. `sub` names the wallet of the first evaluated chain family
    // (EVM first), which is the EVM wallet here because every condition is EVM.
    if (String(claims.sub).toLowerCase() !== wallet.toLowerCase()) {
      return res.status(403).json({ error: "Token is for a different wallet" });
    }
    if (!conditionsMatch(claims.results)) return res.status(403).json({ error: "Unexpected conditions" });
    if (claims.pass !== true) return res.status(403).json({ error: "Conditions not met", attestationId: claims.jti });

    // Reject replays by token id, never by token bytes: the same signed claims can be
    // re-encoded into a different valid token without the key, so bytes are not unique.
    // Keep each id past exp by the verifier's clock-skew allowance, which also accepts it.
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of seenJti) if (exp + DEFAULT_CLOCK_SKEW_SECONDS < now) seenJti.delete(jti);
    if (typeof claims.jti !== "string" || seenJti.has(claims.jti)) {
      return res.status(403).json({ error: "Token already used" });
    }
    seenJti.set(claims.jti, claims.exp);

    res.json({ message: "Welcome", attestationId: claims.jti });
  } catch (err) {
    res.status(400).json({ error: "Invalid token" });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

if (!API_KEY) {
  console.error("Set INSUMER_API_KEY (used by /api/premium)");
  process.exit(1);
}
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
