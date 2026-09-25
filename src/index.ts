/**
 * insumer-verify — Reference verifier for InsumerAPI attestations.
 *
 * Validates ECDSA P-256 signatures, condition hashes, block freshness,
 * and attestation expiry using the Web Crypto API. Zero dependencies.
 * Works in Node.js 18+ and modern browsers.
 *
 * Accepts two input formats (auto-detected):
 * - **JWT string**: ES256-signed JWT from POST /v1/attest with format: "jwt"
 * - **Object**: Raw API response object with data.attestation and data.sig
 */

// ── Types ──────────────────────────────────────────────────────────

export interface VerifyResult {
  valid: boolean;
  checks: {
    signature: CheckResult;
    conditionHashes: CheckResult & { failures?: number[] };
    freshness: CheckResult;
    expiry: CheckResult;
    /** Post-quantum companion signature (ML-DSA-65), reported as a fifth, independent verdict. */
    pq: PqCheckResult;
    /**
     * Present only when a response object carries `data.jwt` BESIDE `data.attestation` (what the
     * API returns for `format: "jwt"`). The tokens in that response are verified too, and bound to
     * the attestation verified above, so nothing in the response is left unchecked: the ES256
     * signature of `jwt`, its condition hashes, that it is the token of THIS attestation (`jti`,
     * `pass`, `results`, `exp`), and its `pqJwt` companion, reported under `pq`. A failure here
     * fails `valid`.
     */
    jwt?: CheckResult & { pq?: PqCheckResult };
  };
}

/**
 * Fifth verdict: the post-quantum companion.
 * - `verified`     the companion was present, resolved by pqKid, and verified
 * - `refuted`      the companion was present and FAILED verification (tampered or wrong key)
 * - `absent`       the response carried no companion (normal for artifacts issued before PQ signing)
 * - `unverifiable` the companion was present but could not be checked (pqKid not in JWKS, JWKS
 *                  unreachable, or no ML-DSA implementation available in this runtime)
 * `passed` reflects POLICY, not evidence: `refuted` always fails; `absent`/`unverifiable` fail only
 * when the caller's `pqRequiredFrom` date has passed and `mode` is "access". `existedAtIssuance`
 * is set only when the caller supplies `pqActivatedAt` (the anchored binding date).
 */
export interface PqCheckResult extends CheckResult {
  status: "verified" | "refuted" | "absent" | "unverifiable";
  kid?: string;
  existedAtIssuance?: boolean;
}

export interface CheckResult {
  passed: boolean;
  reason?: string;
}

export interface VerifyOptions {
  /** Maximum acceptable age of blockTimestamp in seconds. Results without blockTimestamp (e.g. XRPL, which uses ledgerIndex/ledgerHash instead) are skipped. */
  maxAge?: number;
  /**
   * Clock-skew allowance in seconds for the freshness and expiry checks (spec Section 9.4
   * RECOMMENDS 60). Default 60; 0 disables it. A blockTimestamp (or profiledAt) may be this
   * much older than `maxAge` allows, and an expiresAt this far in the past is still current.
   * It does not touch the expiresAt-to-attestedAt binding (see EXPIRY_BINDING_GRACE_MS) or
   * the caller's own `pqRequiredFrom` cutoff.
   */
  clockSkew?: number;
  /** JWKS URL for dynamic key discovery. When set, fetches the signing key from this URL instead of using the hardcoded key. Example: "https://insumermodel.com/.well-known/jwks.json" */
  jwksUrl?: string;
  /**
   * A key set you already hold, e.g. a copy of the JWKS kept alongside retained attestations.
   * When set, keys are resolved from this object and nothing is fetched; it takes precedence
   * over `jwksUrl`. Covers both the ECDSA key and the ML-DSA-65 companion key. Keys are never
   * removed from the published JWKS (spec Section 4.2), so a saved copy stays valid for
   * everything signed before it was saved.
   */
  jwks?: { keys: JwksKey[] };
  /**
   * Verification context. "access" (default): the PQ policy below applies to `valid`.
   * "evidence": nothing is refused for lacking a companion; every verdict is reported and, when
   * `pqActivatedAt` is supplied, `pq.existedAtIssuance` says whether the companion existed when the
   * artifact was issued. Use "evidence" when reading an artifact after the fact (audit, dispute).
   */
  mode?: "access" | "evidence";
  /**
   * The verifier's OWN cutoff: at wall-clock time >= this date, an artifact without a verified
   * PQ companion fails `valid` in "access" mode. Nothing inside the artifact can move this date.
   * Undefined (default) = the companion is reported but never required.
   */
  pqRequiredFrom?: string | Date;
  /**
   * The anchored PQ binding date (from /.well-known/pq-key-binding.json). Enables `pq.existedAtIssuance`.
   * Reporting only: it never affects `passed` or `valid`. To enforce the companion, set `pqRequiredFrom`.
   */
  pqActivatedAt?: string | Date;
  /** Companion JWT for the JWT input path (the `pqJwt` sibling of `data.jwt`). Object inputs carry it in `data.pqJwt`. */
  pqJwt?: string;
}

// ── Internal types for parsing ─────────────────────────────────────

interface AttestationResult {
  condition: number;
  evaluatedCondition?: Record<string, unknown>;
  conditionHash?: string;
  blockTimestamp?: string;
  [key: string]: unknown;
}

interface Attestation {
  id: string;
  pass: boolean;
  results: AttestationResult[];
  attestedAt: string;
  expiresAt: string;
  passCount?: number;
  failCount?: number;
}

interface AttestationResponse {
  data: {
    attestation: Attestation;
    sig: string;
    kid?: string;
    pqSig?: string;
    pqKid?: string;
    pqJwt?: string;
  };
}

export interface JwksKey {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  /** RFC 9964: raw ML-DSA public key, base64url (kty "AKP") */
  pub?: string;
  kid?: string;
  use?: string;
  alg?: string;
}

// ── Public key ─────────────────────────────────────────────────────

/**
 * InsumerAPI ECDSA P-256 public key in JWK format.
 * Verifiable via JWKS at https://insumermodel.com/.well-known/jwks.json
 */
const PUBLIC_KEY_JWK: JsonWebKey = {
  kty: "EC",
  x: "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
  y: "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
  crv: "P-256",
};

const DEFAULT_JWKS_URL = "https://insumermodel.com/.well-known/jwks.json";

// ── Clock tolerances ───────────────────────────────────────────────

/**
 * Default clock-skew allowance for the freshness and expiry checks, in seconds
 * (spec Section 9.4 RECOMMENDS 60). Overridden per call by `options.clockSkew`.
 */
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/**
 * Grace on the expiresAt-to-attestedAt binding (spec Check 4, step 2), in milliseconds.
 * An honest expiresAt is exactly attestedAt plus the issuance window; this absorbs rounding
 * and clock skew at that boundary. It is a verifier tolerance the spec permits (up to 60
 * seconds), fixed rather than configurable, and separate from `options.clockSkew`.
 */
export const EXPIRY_BINDING_GRACE_MS = 60 * 1000;

function clockSkewMs(options?: VerifyOptions): number {
  const s = options?.clockSkew;
  const seconds = typeof s === "number" && Number.isFinite(s) ? Math.max(0, s) : DEFAULT_CLOCK_SKEW_SECONDS;
  return seconds * 1000;
}

// ── Helpers ────────────────────────────────────────────────────────

const subtle = globalThis.crypto?.subtle;

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlToBytes(b64url: string): Uint8Array {
  // Convert base64url to standard base64
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  return base64ToBytes(b64);
}

function base64UrlDecode(b64url: string): string {
  const bytes = base64UrlToBytes(b64url);
  return new TextDecoder().decode(bytes);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// The key set to resolve against: a supplied object (nothing fetched) or the JWKS at a URL.
// `label` names the source in error messages.
async function loadJwks(options: VerifyOptions | undefined, fallbackUrl?: string): Promise<{ jwks: { keys: JwksKey[] }; label: string }> {
  if (options?.jwks) {
    if (!options.jwks || !Array.isArray(options.jwks.keys)) throw new Error("Supplied jwks has no keys array");
    return { jwks: options.jwks, label: "supplied JWKS" };
  }
  const url = options?.jwksUrl || fallbackUrl || DEFAULT_JWKS_URL;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`JWKS fetch failed: ${res.status} ${res.statusText}`);
  }
  return { jwks: (await res.json()) as { keys: JwksKey[] }, label: `JWKS at ${url}` };
}

async function fetchJwksKey(options: VerifyOptions | undefined, kid?: string): Promise<JsonWebKey> {
  const { jwks, label } = await loadJwks(options);
  if (!jwks.keys || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error("JWKS response contains no keys");
  }
  // Match by kid when the response names one. A kid that resolves to nothing is a
  // failure, not a reason to fall back: the first key in the document is not the key
  // the signature claims, and accepting it would verify an unknown or forged kid
  // against whichever key happens to be listed first.
  // A response with no kid cannot select a key at all (spec Section 3.4 makes kid
  // mandatory), so that is a failure too: the set holds keys of two types, and
  // position is not a contract.
  if (!kid) {
    throw new Error("Response carries no kid; the signing key cannot be selected");
  }
  const key = jwks.keys.find((k) => k.kid === kid);
  if (!key) {
    throw new Error(`${label} has no key matching kid "${kid}"`);
  }
  if (key.kty !== "EC" || key.crv !== "P-256") {
    throw new Error(`JWKS key "${kid}" is not a P-256 EC key; a classical signature cannot be verified with it`);
  }
  return { kty: key.kty, crv: key.crv, x: key.x, y: key.y };
}

// ── Post-quantum companion (ML-DSA-65, RFC 9964) ───────────────────
//
// The companion is ADDITIVE: `pqSig` signs "insumer.attestation.pq1" + "\n" + the exact
// classical preimage the classical `kid` selects (v1 bare JSON or v2 canonical JSON);
// `pqJwt` is a separate compact JWS (alg "ML-DSA-65") over the same claims as `jwt`.
// The PQ public key is an RFC 9964 JWK (kty "AKP", `pub`) in the same JWKS, resolved by
// `pqKid`. ML-DSA is not in Web Crypto, so verification uses @noble/post-quantum when it is
// installed; when it is not, the verdict is `unverifiable` (never a silent pass, never a
// silent failure) so the caller sees exactly what could not be checked.

const PQ_ATTEST_DOMAIN = "insumer.attestation.pq1";
const PQ_TRUST_DOMAIN = "insumer.trust.pq1";

type MlDsa = { verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean };
let mlDsaPromise: Promise<MlDsa | null> | undefined;
async function loadMlDsa(): Promise<MlDsa | null> {
  if (!mlDsaPromise) {
    mlDsaPromise = (async () => {
      try {
        const modName = "@noble/post-quantum/ml-dsa.js";
        const mod = (await import(/* webpackIgnore: true */ modName)) as { ml_dsa65?: MlDsa };
        return mod.ml_dsa65 ?? null;
      } catch {
        return null;
      }
    })();
  }
  return mlDsaPromise;
}

async function fetchPqKey(options: VerifyOptions | undefined, pqKid: string): Promise<Uint8Array> {
  const { jwks, label } = await loadJwks(options);
  const key = (jwks.keys || []).find((k) => k.kid === pqKid);
  if (!key) throw new Error(`${label} has no key matching pqKid "${pqKid}"`);
  if (key.kty !== "AKP" || key.alg !== "ML-DSA-65" || typeof key.pub !== "string") {
    throw new Error(`JWKS key "${pqKid}" is not an RFC 9964 ML-DSA-65 key`);
  }
  return base64UrlToBytes(key.pub);
}

function pqPolicy(
  status: PqCheckResult["status"],
  options: VerifyOptions | undefined,
  attestedAt?: string
): { passed: boolean; existedAtIssuance?: boolean } {
  let existedAtIssuance: boolean | undefined;
  if (options?.pqActivatedAt && attestedAt) {
    const act = new Date(options.pqActivatedAt).getTime();
    const at = new Date(attestedAt).getTime();
    if (!isNaN(act) && !isNaN(at)) existedAtIssuance = at >= act;
  }
  if (status === "refuted") return { passed: false, existedAtIssuance };
  if (status === "verified") return { passed: true, existedAtIssuance };
  // absent / unverifiable: required only in access mode once the verifier's own date has passed
  const mode = options?.mode ?? "access";
  if (mode === "evidence" || !options?.pqRequiredFrom) return { passed: true, existedAtIssuance };
  const from = new Date(options.pqRequiredFrom).getTime();
  const required = !isNaN(from) && Date.now() >= from;
  return { passed: !required, existedAtIssuance };
}

async function checkPqSignature(
  domain: string,
  classicalPreimage: string,
  pqSig: string | undefined,
  pqKid: string | undefined,
  options: VerifyOptions | undefined,
  attestedAt?: string
): Promise<PqCheckResult> {
  if (!pqSig) {
    const pol = pqPolicy("absent", options, attestedAt);
    return { status: "absent", passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: pol.passed ? "No post-quantum companion on this response" : "Post-quantum companion required from " + String(options?.pqRequiredFrom) + " and absent" };
  }
  if (!pqKid) {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: "pqSig present without pqKid" };
  }
  // A known companion kid that names the other artifact type is a mislabelled artifact:
  // reported as unverifiable, never re-interpreted. An unknown kid falls through to the
  // JWKS lookup and is reported as unresolvable there.
  const expectedPqKid = domain === PQ_TRUST_DOMAIN ? "insumer-trust-pq1" : "insumer-attest-pq1";
  if (KNOWN_PQ_KIDS.has(pqKid) && pqKid !== expectedPqKid) {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: `pqKid "${pqKid}" does not name this artifact type (expected ${expectedPqKid})` };
  }
  const mlDsa = await loadMlDsa();
  if (!mlDsa) {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: "ML-DSA verifier unavailable in this runtime (install @noble/post-quantum)" };
  }
  let publicKey: Uint8Array;
  try {
    publicKey = await fetchPqKey(options, pqKid);
  } catch (e) {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: (e as Error).message };
  }
  try {
    const msg = new TextEncoder().encode(domain + "\n" + classicalPreimage);
    const ok = mlDsa.verify(base64ToBytes(pqSig), msg, publicKey);
    const status: PqCheckResult["status"] = ok ? "verified" : "refuted";
    const pol = pqPolicy(status, options, attestedAt);
    return { status, kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: ok ? undefined : "Post-quantum companion does not verify (tampered payload or wrong key)" };
  } catch (e) {
    const pol = pqPolicy("refuted", options, attestedAt);
    return { status: "refuted", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: `Post-quantum verification error: ${(e as Error).message}` };
  }
}

// First path at which two parsed JSON values differ, or null when they are deeply equal.
// Objects are compared without regard to member order, arrays in order, primitives by value;
// a member present on one side only is a difference. Both inputs come from the same JSON
// parser, so no canonical form is needed. Depth-bounded like every other walker here.
function firstClaimDifference(a: unknown, b: unknown, path: string = "", depth: number = 0): string | null {
  if (depth > MAX_CANONICAL_DEPTH) throw new CanonicalDepthError(MAX_CANONICAL_DEPTH);
  if (a === b) return null;
  const aObj = a !== null && typeof a === "object";
  const bObj = b !== null && typeof b === "object";
  if (!aObj || !bObj || Array.isArray(a) !== Array.isArray(b)) return path;
  if (Array.isArray(a)) {
    const bArr = b as unknown[];
    if (a.length !== bArr.length) return path;
    for (let i = 0; i < a.length; i++) {
      const d = firstClaimDifference(a[i], bArr[i], `${path}[${i}]`, depth + 1);
      if (d !== null) return d;
    }
    return null;
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
  for (const k of Object.keys(ao)) if (!has(bo, k)) return path ? `${path}.${k}` : k;
  for (const k of Object.keys(bo)) if (!has(ao, k)) return path ? `${path}.${k}` : k;
  for (const k of Object.keys(ao)) {
    const d = firstClaimDifference(ao[k], bo[k], path ? `${path}.${k}` : k, depth + 1);
    if (d !== null) return d;
  }
  return null;
}

// pqJwt: compact JWS, alg ML-DSA-65, same claims as the ES256 JWT. Verified over its own
// header.payload bytes, then bound to the classical JWT by the full claim set: the two payloads
// must carry the same member names with deeply equal values, so the companion vouches for
// every claim a relying party reads from the ES256 JWT, and cannot be transplanted from
// another artifact. Byte identity of the payload segments is sufficient but never required.
async function checkPqJwt(
  pqJwt: string | undefined,
  classical: JwtParts | undefined,
  options: VerifyOptions | undefined,
  attestedAt?: string
): Promise<PqCheckResult> {
  if (!pqJwt) {
    // A bare JWT string cannot carry its companion: it travels in options.pqJwt. The reason
    // names the call rather than the artifact, so that a call which supplied no companion stays
    // distinguishable from an artifact that carries none. The two warrant different action
    // under pqRequiredFrom, so the distinction has to survive into the reason.
    const pol = pqPolicy("absent", options, attestedAt);
    return { status: "absent", passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: pol.passed ? "No pqJwt was supplied to this call; pass options.pqJwt (a bare token string cannot carry its companion)" : "Post-quantum companion required from " + String(options?.pqRequiredFrom) + " and absent" };
  }
  let parts: JwtParts;
  try {
    parts = parseJwt(pqJwt);
  } catch (e) {
    const pol = pqPolicy("refuted", options, attestedAt);
    return { status: "refuted", passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: `pqJwt parse error: ${(e as Error).message}` };
  }
  const pqKid = parts.header.kid as string | undefined;
  if (parts.header.alg !== "ML-DSA-65" || !pqKid) {
    const pol = pqPolicy("refuted", options, attestedAt);
    return { status: "refuted", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: `pqJwt header must carry alg ML-DSA-65 and a kid (got alg ${String(parts.header.alg)})` };
  }
  if (KNOWN_PQ_KIDS.has(pqKid) && pqKid !== "insumer-attest-pq1") {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: `pqJwt kid "${pqKid}" does not name an attestation companion (expected insumer-attest-pq1)` };
  }
  const mlDsa = await loadMlDsa();
  if (!mlDsa) {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: "ML-DSA verifier unavailable in this runtime (install @noble/post-quantum)" };
  }
  let publicKey: Uint8Array;
  try {
    publicKey = await fetchPqKey(options, pqKid);
  } catch (e) {
    const pol = pqPolicy("unverifiable", options, attestedAt);
    return { status: "unverifiable", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: (e as Error).message };
  }
  const signingInput = new TextEncoder().encode(`${parts.headerB64}.${parts.payloadB64}`);
  const ok = mlDsa.verify(parts.signatureBytes, signingInput, publicKey);
  if (!ok) {
    const pol = pqPolicy("refuted", options, attestedAt);
    return { status: "refuted", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: "pqJwt signature does not verify" };
  }
  if (classical) {
    if (parts.payloadB64 !== classical.payloadB64) {
      // Nesting past the bound cannot be compared, and what cannot be shown equal is not bound.
      let claim: string | null;
      try {
        claim = firstClaimDifference(parts.payload, classical.payload);
      } catch (e) {
        if ((e as Error)?.name !== "CanonicalDepthError") throw e;
        claim = "(nested too deeply to compare)";
      }
      if (claim !== null) {
        const pol = pqPolicy("refuted", options, attestedAt);
        return { status: "refuted", kid: pqKid, passed: pol.passed, existedAtIssuance: pol.existedAtIssuance, reason: `pqJwt claim "${claim}" differs from the ES256 JWT` };
      }
    }
  }
  const pol = pqPolicy("verified", options, attestedAt);
  return { status: "verified", kid: pqKid, passed: true, existedAtIssuance: pol.existedAtIssuance };
}

function parseResponse(response: unknown): AttestationResponse {
  const obj = response as Record<string, unknown>;
  const data = obj?.data as Record<string, unknown> | undefined;
  if (!data || typeof data !== "object") {
    throw new Error("Invalid response: missing data object");
  }
  const attestation = data.attestation as Attestation | undefined;
  const sig = data.sig as string | undefined;
  if (!attestation || typeof attestation !== "object") {
    throw new Error("Invalid response: missing data.attestation");
  }
  if (typeof sig !== "string" || sig.length === 0) {
    throw new Error("Invalid response: missing data.sig");
  }
  if (typeof attestation.id !== "string") {
    throw new Error("Invalid response: missing attestation.id");
  }
  if (typeof attestation.pass !== "boolean") {
    throw new Error("Invalid response: missing attestation.pass");
  }
  if (!Array.isArray(attestation.results)) {
    throw new Error("Invalid response: missing attestation.results");
  }
  if (typeof attestation.attestedAt !== "string") {
    throw new Error("Invalid response: missing attestation.attestedAt");
  }
  if (typeof attestation.expiresAt !== "string") {
    throw new Error("Invalid response: missing attestation.expiresAt");
  }
  const kid = data.kid as string | undefined;
  const pqSig = typeof data.pqSig === "string" ? (data.pqSig as string) : undefined;
  const pqKid = typeof data.pqKid === "string" ? (data.pqKid as string) : undefined;
  const pqJwt = typeof data.pqJwt === "string" ? (data.pqJwt as string) : undefined;
  return { data: { attestation, sig, kid, pqSig, pqKid, pqJwt } };
}

// ── JWT parsing ───────────────────────────────────────────────────

interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  headerB64: string;
  payloadB64: string;
  signatureBytes: Uint8Array;
}

function parseJwt(token: string): JwtParts {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT: expected 3 dot-separated segments");
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(base64UrlDecode(headerB64));
  } catch {
    throw new Error("Invalid JWT: malformed header");
  }
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64));
  } catch {
    throw new Error("Invalid JWT: malformed payload");
  }

  const isObject = (v: unknown) => v !== null && typeof v === "object" && !Array.isArray(v);
  if (!isObject(header)) throw new Error("Invalid JWT: header is not a JSON object");
  if (!isObject(payload)) throw new Error("Invalid JWT: payload is not a JSON object");

  const signatureBytes = base64UrlToBytes(sigB64);

  return { header, payload, headerB64, payloadB64, signatureBytes };
}

/**
 * Convert a DER-encoded ECDSA signature to raw IEEE P1363 format (r || s).
 * jose/Node.js crypto may produce DER signatures; Web Crypto expects P1363.
 */
function derToP1363(der: Uint8Array, keySize: number = 32): Uint8Array {
  if (der[0] !== 0x30) return der; // Not DER, assume already P1363
  let offset = 2;
  // Parse r
  if (der[offset] !== 0x02) return der;
  offset++;
  const rLen = der[offset]; offset++;
  let r = der.slice(offset, offset + rLen);
  offset += rLen;
  // Parse s
  if (der[offset] !== 0x02) return der;
  offset++;
  const sLen = der[offset]; offset++;
  let s = der.slice(offset, offset + sLen);
  // Remove leading zero padding
  if (r.length > keySize) r = r.slice(r.length - keySize);
  if (s.length > keySize) s = s.slice(s.length - keySize);
  // Pad to fixed keySize
  const result = new Uint8Array(keySize * 2);
  result.set(r, keySize - r.length);
  result.set(s, keySize * 2 - s.length);
  return result;
}

// ── Verification checks ───────────────────────────────────────────

// v2 signing scheme: domain-separated, recursive-sorted-key canonical JSON.
// The kid on the response selects the scheme: insumer-attest-v1 (bare JSON, frozen),
// insumer-attest-v2 (domain "insumer.attestation.v2" + canonical JSON).
const V2_ATTEST_DOMAIN = "insumer.attestation.v2";

// Which classical kids may sign which artifact. Attestations and trust profiles share the
// v1 kid (one frozen scheme) but have distinct v2 kids; a trust kid on an attestation, or
// the reverse, is a mislabelled artifact and fails Check 1 rather than being re-interpreted.
const ATTEST_KIDS = new Set(["insumer-attest-v1", "insumer-attest-v2"]);
const TRUST_KIDS = new Set(["insumer-attest-v1", "insumer-trust-v2"]);
const KNOWN_PQ_KIDS = new Set(["insumer-attest-pq1", "insumer-trust-pq1"]);
// Every classical kid this library knows, across both artifact types. Used ONLY by the
// rotation guard below, which must distinguish a kid it has never met from a known kid
// that names the wrong artifact type. The latter is a relabelled artifact and keeps its
// long-standing "refuted" verdict (published vector 21-trust-under-attest-kid).
const KNOWN_CLASSICAL_KIDS = new Set([...ATTEST_KIDS, ...TRUST_KIDS]);
function kidProblem(kid: string | undefined, allowed: Set<string>, artifact: string): string | undefined {
  if (!kid) return `Response carries no kid; the signing key and scheme cannot be selected (${artifact})`;
  if (!allowed.has(kid)) return `kid "${kid}" does not sign ${artifact}s`;
  return undefined;
}

/**
 * Runs one check so that a thrown error becomes a FAILED CHECK, never an escape.
 *
 * Why per-check and not one try/catch around Promise.all: Promise.all rejects on
 * the first failure but leaves its siblings running, and a sibling that throws
 * afterwards lands as an UNHANDLED REJECTION. Node >=15 exits the process on
 * those, and the caller's own try/catch cannot prevent it — a correctly written
 * caller still dies. Guarding each check individually means Promise.all can never
 * reject at all, so no sibling is ever orphaned.
 *
 * The thunk is called in here (not evaluated at the call site) so that an argument
 * which throws synchronously — building a signing preimage from a hostile artifact,
 * say — is caught on this path too.
 */
async function guardedCheck<T>(
  thunk: () => T | Promise<T>,
  onFailure: (reason: string) => T
): Promise<T> {
  try {
    return await thunk();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const depthRefusal =
      (e as Error)?.name === "CanonicalDepthError" || e instanceof RangeError;
    return onFailure(
      depthRefusal
        ? `Refused: artifact too deeply nested to verify (${msg})`
        : `Verification error: ${msg}`
    );
  }
}

/** Failed-check shapes for the two result types the checks return. */
const failedCheck = (reason: string): CheckResult => ({ passed: false, reason });
/**
 * The companion signs the post-quantum domain tag plus the EXACT classical preimage the
 * classical kid selects. A kid this verifier does not know selects no preimage, so the
 * companion cannot be evaluated at all.
 *
 * Substituting another era's preimage would check the companion against bytes the issuer
 * never signed, which can only produce a false "refuted" — the strongest verdict available,
 * and one the spec says MUST fail the artifact. Key rotations are two-sided: a verifier has
 * to tolerate a signing kid it has not met, and tolerating one means declining to guess at
 * its preimage. Spec Section 12, Check 6.
 *
 * Returns undefined when the caller should proceed normally.
 */
function unknownClassicalKidPq(
  kid: string | undefined,
  pqSig: string | undefined,
  pqKid: string | undefined,
  options: VerifyOptions | undefined,
  at?: string
): PqCheckResult | undefined {
  if (!pqSig) return undefined; // absence is checkPqSignature's verdict to report
  // A KNOWN kid that names the other artifact type is a relabelled artifact, not a
  // rotation: the preimage it selects is well defined, the untouched companion cannot
  // verify against it, and "refuted" is the right and long-published verdict. Only a kid
  // this verifier has never met leaves it with no preimage to rebuild.
  if (kid !== undefined && KNOWN_CLASSICAL_KIDS.has(kid)) return undefined;
  const pol = pqPolicy("unverifiable", options, at);
  return {
    status: "unverifiable",
    ...(pqKid ? { kid: pqKid } : {}),
    passed: pol.passed,
    existedAtIssuance: pol.existedAtIssuance,
    reason: `Classical kid ${kid === undefined ? "(absent)" : `"${kid}"`} is unknown to this verifier, so the preimage the companion signs cannot be reconstructed`,
  };
}

const failedPqCheck = (reason: string): PqCheckResult => ({
  status: "unverifiable",
  passed: false,
  reason,
});

// The exact bytes the server signed, selected by scheme (kid).
// v1: bare JSON.stringify({ id, pass, results, attestedAt }).
// v2: domain tag + "\n" + canonical JSON of { v:2, id, pass, results, attestedAt }.
function classicalAttestPreimage(attestation: Attestation, kid?: string): string {
  return kid === "insumer-attest-v2"
    ? V2_ATTEST_DOMAIN +
        "\n" +
        canonicalize({
          v: 2,
          id: attestation.id,
          pass: attestation.pass,
          results: attestation.results,
          attestedAt: attestation.attestedAt,
        })
    : (assertDepth(attestation.results),
      JSON.stringify({
        id: attestation.id,
        pass: attestation.pass,
        results: attestation.results,
        attestedAt: attestation.attestedAt,
      }));
}

/**
 * Maximum nesting depth this verifier will canonicalize.
 *
 * Canonicalization runs alongside signature verification, not after it, so the
 * recursive walk below is reachable by anyone holding an artifact — a signature
 * does not have to be valid to get here. Unbounded, a deeply nested artifact
 * exhausts the call stack. `JSON.parse` is no defence: V8's parser is iterative
 * and accepts ~1,000,000 levels, far past what this walk survives.
 *
 * 128 open containers matches the bound A2A PR #2246 and in-toto/attestation
 * PR #570 propose, so a verifier that refuses here refuses what they refuse.
 * The deepest artifact in the published conformance corpus nests 9 levels, so
 * this leaves roughly 14x headroom over anything the API actually issues.
 */
export const MAX_CANONICAL_DEPTH = 128;

/** Thrown when an artifact nests past MAX_CANONICAL_DEPTH. Callers turn this
 *  into a failed check — it is a refusal to verify, never a passing verdict. */
class CanonicalDepthError extends Error {
  constructor(limit: number) {
    super(`Artifact nests deeper than ${limit} levels; refusing to canonicalize`);
    this.name = "CanonicalDepthError";
  }
}

// NOTE: the recursive calls below pass `depth` explicitly rather than using
// `value.map(canonicalize)`. Array.prototype.map invokes its callback with
// (element, index, array), so the bare reference would feed the array INDEX in
// as the depth and silently defeat the bound.
function canonicalize(value: unknown, depth: number = 0): string {
  if (depth > MAX_CANONICAL_DEPTH) throw new CanonicalDepthError(MAX_CANONICAL_DEPTH);
  if (Array.isArray(value))
    return "[" + value.map((v) => canonicalize(v, depth + 1)).join(",") + "]";
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(o)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + canonicalize(o[k], depth + 1))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

/** Depth-bounded stand-in for JSON.stringify on the v1 (bare-JSON) paths.
 *  v1 preimages are frozen, so this MUST NOT alter the bytes: it walks the
 *  value only to enforce the same bound, then stringifies exactly as before. */
function assertDepth(value: unknown, depth: number = 0): void {
  if (depth > MAX_CANONICAL_DEPTH) throw new CanonicalDepthError(MAX_CANONICAL_DEPTH);
  if (Array.isArray(value)) {
    for (const v of value) assertDepth(v, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) assertDepth(v, depth + 1);
  }
}

async function checkSignature(
  attestation: Attestation,
  sig: string,
  keyJwk?: JsonWebKey,
  kid?: string
): Promise<CheckResult> {
  if (!subtle) {
    return { passed: false, reason: "Web Crypto API not available" };
  }
  const problem = kidProblem(kid, ATTEST_KIDS, "attestation");
  if (problem) return { passed: false, reason: problem };

  try {
    const key = await subtle.importKey(
      "jwk",
      keyJwk || PUBLIC_KEY_JWK,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    const payload = classicalAttestPreimage(attestation, kid);

    const payloadBytes = new TextEncoder().encode(payload);
    const sigBytes = base64ToBytes(sig);

    const valid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes.buffer as ArrayBuffer,
      payloadBytes
    );

    return valid
      ? { passed: true }
      : { passed: false, reason: "Signature does not match payload" };
  } catch (e) {
    return {
      passed: false,
      reason: `Signature verification error: ${(e as Error).message}`,
    };
  }
}

async function checkJwtSignature(
  jwt: JwtParts,
  keyJwk?: JsonWebKey
): Promise<CheckResult> {
  if (!subtle) {
    return { passed: false, reason: "Web Crypto API not available" };
  }

  const jwtKidProblem = kidProblem(jwt.header.kid as string | undefined, ATTEST_KIDS, "attestation");
  if (jwtKidProblem) return { passed: false, reason: jwtKidProblem };

  try {
    if (jwt.header.alg !== "ES256") {
      return { passed: false, reason: `Unsupported JWT algorithm: ${jwt.header.alg}` };
    }

    const key = await subtle.importKey(
      "jwk",
      keyJwk || PUBLIC_KEY_JWK,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    // JWT signature is over "header.payload" (the raw base64url segments)
    const signingInput = new TextEncoder().encode(
      `${jwt.headerB64}.${jwt.payloadB64}`
    );

    // JWT ES256 signatures should be raw r||s (P1363, 64 bytes)
    // but some libraries produce DER encoding — handle both
    let sigBytes = jwt.signatureBytes;
    if (sigBytes.length !== 64) {
      sigBytes = derToP1363(sigBytes);
    }

    const valid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes.buffer as ArrayBuffer,
      signingInput
    );

    return valid
      ? { passed: true }
      : { passed: false, reason: "JWT signature does not match payload" };
  } catch (e) {
    return {
      passed: false,
      reason: `JWT signature verification error: ${(e as Error).message}`,
    };
  }
}

async function checkConditionHashes(
  results: AttestationResult[],
  kid?: string
): Promise<CheckResult & { failures?: number[] }> {
  if (!subtle) {
    return { passed: false, reason: "Web Crypto API not available" };
  }

  const failures: number[] = [];
  const isV2 = kid === "insumer-attest-v2";

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    // Every result MUST carry both (spec Section 8); a result that lacks either cannot be
    // recomputed and is recorded as a failure rather than silently passed over.
    if (!r.evaluatedCondition || !r.conditionHash) {
      failures.push(i);
      continue;
    }

    // Canonical JSON, matching the server by scheme: v1 = sorted-key array-replacer;
    // v2 = recursive-sorted-key canonical JSON.
    const canonical = isV2
      ? canonicalize(r.evaluatedCondition)
      : (assertDepth(r.evaluatedCondition),
        JSON.stringify(
          r.evaluatedCondition,
          Object.keys(r.evaluatedCondition).sort()
        ));
    const hashBuffer = await subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical)
    );
    const computed = "0x" + bytesToHex(new Uint8Array(hashBuffer));

    if (computed !== r.conditionHash) {
      failures.push(i);
    }
  }

  if (failures.length > 0) {
    return {
      passed: false,
      failures,
      reason: `Condition hash mismatch at result index(es): ${failures.join(", ")}`,
    };
  }

  return { passed: true };
}

// Freshness (spec Check 3): blockTimestamp age against the caller's maxAge, with the
// clock-skew allowance from options.clockSkew (Section 9.4) added to the limit.
function checkFreshness(
  results: AttestationResult[],
  maxAge: number | undefined,
  skewMs: number
): CheckResult {
  if (maxAge === undefined) {
    return { passed: true, reason: "Freshness check skipped (no maxAge)" };
  }

  const now = Date.now();
  const maxAgeMs = maxAge * 1000;

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (!r.blockTimestamp) continue; // some chains lack blockTimestamp

    const age = now - new Date(r.blockTimestamp).getTime();
    if (age > maxAgeMs + skewMs) {
      return {
        passed: false,
        reason: `Result ${i} blockTimestamp is ${Math.round(age / 1000)}s old (max: ${maxAge}s + ${skewMs / 1000}s clock skew)`,
      };
    }
  }

  return { passed: true };
}

// Expiry (spec Check 4). Step 1 binds the unsigned expiresAt to the signed attestedAt
// under EXPIRY_BINDING_GRACE_MS; step 2 compares expiresAt to the clock, with the
// clock-skew allowance from options.clockSkew.
function checkExpiry(
  expiresAt: string,
  skewMs: number,
  attestedAt?: string,
  results?: AttestationResult[]
): CheckResult {
  const ts = new Date(expiresAt).getTime();
  if (isNaN(ts)) {
    return { passed: false, reason: "Invalid expiresAt timestamp" };
  }

  // Bind the (unsigned) expiresAt to the SIGNED attestedAt. The API never issues a
  // validity window longer than 30 minutes (5 for a delegation verdict), and attestedAt
  // is inside the signed preimage while expiresAt is not: an expiresAt more than one
  // window past attestedAt can only have been edited after signing. Rejecting it closes
  // offline replay of an expired attestation whose expiresAt was pushed to a future date.
  // An honest attestation is unaffected: its expiresAt is exactly attestedAt + the window,
  // and EXPIRY_BINDING_GRACE_MS absorbs rounding at that boundary.
  // attestedAt is omitted on the JWT path, where exp already lives inside the signed token.
  if (attestedAt) {
    const at = new Date(attestedAt).getTime();
    if (!isNaN(at)) {
      const hasDelegation =
        Array.isArray(results) &&
        results.some(
          (r) =>
            !!r.evaluatedCondition &&
            (r.evaluatedCondition as Record<string, unknown>).type ===
              "erc7710_delegation"
        );
      const maxWindowMs = (hasDelegation ? 5 : 30) * 60 * 1000;
      if (ts - at > maxWindowMs + EXPIRY_BINDING_GRACE_MS) {
        return {
          passed: false,
          reason:
            "expiresAt exceeds the signed issuance window (attestedAt + max); treated as tampered",
        };
      }
    }
  }

  if (Date.now() > ts + skewMs) {
    return { passed: false, reason: "Attestation has expired" };
  }

  return { passed: true };
}

// ── JWT verification path ─────────────────────────────────────────

// A format:"jwt" response carries the tokens BESIDE the attestation. Verifying the attestation
// says nothing about them, and a caller goes on to read claims (the wallet, in `sub`) from the
// jwt, so they are verified here as well and bound to the attestation already verified:
// same key as the response kid names, ES256 over header.payload, condition hashes, then
// jti/pass/results/exp equal to the attestation's, then the pqJwt companion over the full claim set.
async function checkEmbeddedJwt(
  token: unknown,
  pqJwt: unknown,
  attestation: Attestation,
  responseKid: string | undefined,
  keyJwk: JsonWebKey | undefined,
  options: VerifyOptions | undefined
): Promise<CheckResult & { pq?: PqCheckResult }> {
  if (typeof token !== "string") {
    return { passed: false, reason: typeof pqJwt === "string" ? "Response carries data.pqJwt without a data.jwt string" : "data.jwt is not a string" };
  }
  let jwt: JwtParts;
  try {
    jwt = parseJwt(token);
  } catch (e) {
    return { passed: false, reason: `data.jwt: ${(e as Error).message}` };
  }
  if (jwt.header.kid !== responseKid) {
    return { passed: false, reason: `data.jwt names kid "${String(jwt.header.kid)}" but the response is signed under "${String(responseKid)}"` };
  }
  // From here the token is parsed and names this response's kid, so the companion has a
  // classical token to be bound to and its verdict is reported whatever a later check
  // decides. Check 6 calls the companion its own verdict, and it stays informative on a
  // failing artifact: a corrupted signature over a genuine, companion-attested payload and a
  // forged payload are different findings, and the companion verdict is what tells them apart.
  //
  // It must not move any earlier: checkPqJwt only compares claim sets when it is handed a
  // parsed classical token, so computing it before the parse and kid checks would report
  // "verified" beside something that is not this response's jwt.
  const pq = await checkPqJwt(typeof pqJwt === "string" ? pqJwt : undefined, jwt, options, attestation.attestedAt);
  const fail = (reason: string): CheckResult & { pq?: PqCheckResult } => ({ passed: false, pq, reason });

  const signature = await checkJwtSignature(jwt, keyJwk);
  if (!signature.passed) return fail(`data.jwt signature: ${signature.reason ?? "does not verify"}`);

  const p = jwt.payload;
  const expSeconds = Math.floor(Date.parse(attestation.expiresAt) / 1000);
  const bindings: Array<[string, unknown, unknown]> = [
    ["jti", p.jti, attestation.id],
    ["pass", p.pass, attestation.pass],
    ["results", p.results, attestation.results],
    ["exp", p.exp, expSeconds],
  ];
  for (const [name, a, b] of bindings) {
    const d = firstClaimDifference(a, b, name);
    if (d !== null) return fail(`data.jwt claim "${d}" differs from the attestation in the same response`);
  }
  const hashes = await checkConditionHashes((p.results || []) as AttestationResult[], responseKid);
  if (!hashes.passed) return fail(`data.jwt condition hashes: ${hashes.reason ?? "failed"}`);

  if (!pq.passed) return fail(`data.pqJwt: ${pq.reason ?? pq.status}`);
  return { passed: true, pq };
}

async function verifyJwt(
  token: string,
  options?: VerifyOptions
): Promise<VerifyResult> {
  let jwt: JwtParts;
  try {
    jwt = parseJwt(token);
  } catch (e) {
    return {
      valid: false,
      checks: {
        signature: { passed: false, reason: `JWT parse error: ${(e as Error).message}` },
        conditionHashes: { passed: false, reason: "Skipped (JWT parse failed)" },
        freshness: { passed: false, reason: "Skipped (JWT parse failed)" },
        expiry: { passed: false, reason: "Skipped (JWT parse failed)" },
        pq: { status: "unverifiable", passed: false, reason: "Skipped (JWT parse failed)" },
      },
    };
  }

  const p = jwt.payload;

  // Resolve the signing key by the JWT's kid: from options.jwks when supplied, else the JWKS URL
  const kid = jwt.header.kid as string | undefined;

  let keyJwk: JsonWebKey | undefined;
  try {
    keyJwk = await fetchJwksKey(options, kid);
  } catch (e) {
    return {
      valid: false,
      checks: {
        signature: { passed: false, reason: `JWKS fetch error: ${(e as Error).message}` },
        conditionHashes: { passed: false, reason: "Skipped (JWKS fetch failed)" },
        freshness: { passed: false, reason: "Skipped (JWKS fetch failed)" },
        expiry: { passed: false, reason: "Skipped (JWKS fetch failed)" },
        pq: { status: "unverifiable", passed: false, reason: "Skipped (JWKS fetch failed)" },
      },
    };
  }

  // Extract attestation data from JWT claims
  const results = (p.results || []) as AttestationResult[];

  // JWT exp → expiresAt ISO string
  const expUnix = p.exp as number | undefined;
  const expiresAt = expUnix ? new Date(expUnix * 1000).toISOString() : "";

  const iatUnix = p.iat as number | undefined;
  const attestedAt = iatUnix ? new Date(iatUnix * 1000).toISOString() : undefined;

  const skewMs = clockSkewMs(options);
  const [signature, conditionHashes, freshness, expiry, pq] = await Promise.all([
    guardedCheck(() => checkJwtSignature(jwt, keyJwk), failedCheck),
    guardedCheck(() => checkConditionHashes(results, kid), failedCheck),
    guardedCheck(() => checkFreshness(results, options?.maxAge, skewMs), failedCheck),
    guardedCheck(() => checkExpiry(expiresAt, skewMs), failedCheck),
    guardedCheck(() => checkPqJwt(options?.pqJwt, jwt, options, attestedAt), failedPqCheck),
  ]);

  const valid =
    signature.passed &&
    conditionHashes.passed &&
    freshness.passed &&
    expiry.passed &&
    pq.passed;

  return { valid, checks: { signature, conditionHashes, freshness, expiry, pq } };
}

// ── Main export ────────────────────────────────────────────────────

/**
 * Verify an InsumerAPI attestation response.
 *
 * Auto-detects input format:
 * - **String** → JWT verification path (ES256 signature via JWKS)
 * - **Object** → Raw attestation response path (ECDSA P1363 signature)
 *
 * Both formats report the same five independent verdicts:
 * 1. **Signature** — ECDSA P-256 verification, key and scheme selected by kid
 * 2. **Condition hashes** — SHA-256 of canonical JSON per the scheme the kid selects
 * 3. **Freshness** — blockTimestamp age vs caller-defined maxAge (optional)
 * 4. **Expiry** — whether the attestation window has elapsed, bounded by the signed attestedAt
 * 5. **Post-quantum companion** — verified / refuted / absent / unverifiable (spec Check 6)
 *
 * @param response JWT string or full API response object
 * @param options Optional configuration: maxAge (seconds), clockSkew (seconds, default 60), jwksUrl, jwks (a saved key set; nothing fetched)
 * @returns Structured result with overall validity and per-check details
 */
export async function verifyAttestation(
  response: unknown,
  options?: VerifyOptions
): Promise<VerifyResult> {
  // Auto-detect: string → JWT, object → raw attestation
  if (typeof response === "string") {
    return verifyJwt(response, options);
  }

  // An object carrying data.jwt (and optionally data.pqJwt) but no data.attestation is the
  // JWT-format response envelope: route it to the JWT path with its companion attached.
  const maybe = response as { data?: { jwt?: unknown; pqJwt?: unknown; attestation?: unknown } };
  if (maybe && typeof maybe === "object" && maybe.data && typeof maybe.data.jwt === "string" && !maybe.data.attestation) {
    return verifyJwt(maybe.data.jwt, { ...options, pqJwt: typeof maybe.data.pqJwt === "string" ? maybe.data.pqJwt : options?.pqJwt });
  }

  const parsed = parseResponse(response);
  const { attestation, sig, kid, pqSig, pqKid } = parsed.data;
  const hasEmbeddedJwt = !!(maybe && typeof maybe === "object" && maybe.data && (maybe.data.jwt != null || maybe.data.pqJwt != null)); // null or missing = no token to read

  // If a key set (jwks) or jwksUrl is provided, resolve the signing key by kid from it
  let keyJwk: JsonWebKey | undefined;
  if (options?.jwks || options?.jwksUrl) {
    try {
      keyJwk = await fetchJwksKey(options, kid);
    } catch (e) {
      return {
        valid: false,
        checks: {
          signature: { passed: false, reason: `JWKS fetch error: ${(e as Error).message}` },
          conditionHashes: { passed: false, reason: "Skipped (JWKS fetch failed)" },
          freshness: { passed: false, reason: "Skipped (JWKS fetch failed)" },
          expiry: { passed: false, reason: "Skipped (JWKS fetch failed)" },
          pq: { status: "unverifiable", passed: false, reason: "Skipped (JWKS fetch failed)" },
        },
      };
    }
  }

  const skewMs = clockSkewMs(options);
  const [signature, conditionHashes, freshness, expiry, pq] = await Promise.all([
    guardedCheck(() => checkSignature(attestation, sig, keyJwk, kid), failedCheck),
    guardedCheck(() => checkConditionHashes(attestation.results, kid), failedCheck),
    guardedCheck(() => checkFreshness(attestation.results, options?.maxAge, skewMs), failedCheck),
    guardedCheck(
      () => checkExpiry(attestation.expiresAt, skewMs, attestation.attestedAt, attestation.results),
      failedCheck
    ),
    // classicalAttestPreimage() is called INSIDE the thunk: it canonicalizes the
    // artifact, so on a hostile one it throws, and as a bare argument that throw
    // would escape before Promise.all was ever reached.
    guardedCheck(
      () =>
        unknownClassicalKidPq(kid, pqSig, pqKid, options, attestation.attestedAt) ??
        checkPqSignature(
          PQ_ATTEST_DOMAIN,
          classicalAttestPreimage(attestation, kid),
          pqSig,
          pqKid,
          options,
          attestation.attestedAt
        ),
      failedPqCheck
    ),
  ]);

  const failedJwtCheck = (reason: string): CheckResult & { pq?: PqCheckResult } => ({ passed: false, reason });
  const jwtCheck = hasEmbeddedJwt
    ? await guardedCheck(() => checkEmbeddedJwt(maybe.data!.jwt, maybe.data!.pqJwt, attestation, kid, keyJwk, options), failedJwtCheck)
    : undefined;

  const valid =
    signature.passed &&
    conditionHashes.passed &&
    freshness.passed &&
    expiry.passed &&
    pq.passed &&
    (jwtCheck ? jwtCheck.passed : true);

  return {
    valid,
    checks: {
      signature,
      conditionHashes,
      freshness,
      expiry,
      pq,
      ...(jwtCheck ? { jwt: jwtCheck } : {}),
    },
  };
}

// ── Trust profile verification ─────────────────────────────────────
//
// POST /v1/trust returns { ok, data: { trust, sig, kid }, meta }; each entry
// of POST /v1/trust/batch carries the same { trust, sig, kid } shape.
//
// The kid selects the scheme, exactly as it does for attestations:
//   insumer-attest-v1 → bare JSON.stringify(trust)            (v1, frozen)
//   insumer-trust-v2  → "insumer.trust.v2\n" + canonical JSON (v2, domain-separated)
//
// A trust profile is signed as a whole. Unlike an attestation there are no
// per-result conditionHash values, so there is no condition-hash check here.

const V2_TRUST_DOMAIN = "insumer.trust.v2";
const V2_TRUST_KID = "insumer-trust-v2";

/** Signed trust-profile payload from POST /v1/trust. */
export interface TrustProfile {
  id: string;
  wallet: string;
  conditionSetVersion: string;
  dimensions: unknown;
  summary: Record<string, unknown>;
  profiledAt: string;
  expiresAt: string;
  [key: string]: unknown;
}

export interface TrustVerifyResult {
  valid: boolean;
  /**
   * The trust profile whose signature was verified — the exact object parsed
   * from the wire. Render THIS (gated on `valid`), never your own copy of the
   * response, so a caller cannot display a different object than the one that
   * was actually checked. Undefined when parsing failed (no profile identified).
   */
  trust?: TrustProfile;
  checks: {
    signature: CheckResult;
    freshness: CheckResult;
    expiry: CheckResult;
    /** Post-quantum companion (pqKid insumer-trust-pq1), reported as a fourth, independent verdict. */
    pq: PqCheckResult;
  };
}

interface ParsedTrustResponse {
  trust: TrustProfile;
  sig: string;
  kid?: string;
  pqSig?: string;
  pqKid?: string;
}

/**
 * Accepts either the full API response ({ data: { trust, sig, kid } }) or the
 * inner { trust, sig, kid } object (as found in a /v1/trust/batch entry).
 *
 * The returned `trust` is the object exactly as parsed from the wire — its key
 * order is NOT rebuilt, because the v1 scheme signs bare JSON.stringify output
 * and therefore depends on insertion order.
 */
function parseTrustResponse(response: unknown): ParsedTrustResponse {
  if (!response || typeof response !== "object") {
    throw new Error("Response must be an object");
  }
  const root = response as Record<string, unknown>;

  let holder: Record<string, unknown> = root;
  const data = root.data;
  if (data && typeof data === "object" && (data as Record<string, unknown>).trust) {
    holder = data as Record<string, unknown>;
  }

  const trust = holder.trust;
  if (!trust || typeof trust !== "object") {
    throw new Error("Missing trust profile (expected data.trust or trust)");
  }

  // Structural gate. The v1 scheme signs a bare-JSON preimage that carries no type
  // binding, and one kid covers every v1 artifact, so a non-trust object signed by the
  // same key could otherwise satisfy a trust-profile check. Require the distinguishing
  // trust shape: wallet + dimensions + summary + profiledAt appear together only on a
  // trust profile. v2 carries a domain tag, which binds the type on its own; this gate
  // is therefore v1's equivalent and is harmless for v2.
  const t = trust as Record<string, unknown>;
  const looksLikeTrust =
    typeof t.wallet === "string" &&
    typeof t.profiledAt === "string" &&
    typeof t.expiresAt === "string" &&
    t.dimensions !== null && typeof t.dimensions === "object" &&
    t.summary !== null && typeof t.summary === "object";
  if (!looksLikeTrust) {
    throw new Error(
      "Object is not a trust profile (expected wallet, dimensions, summary, profiledAt, expiresAt)"
    );
  }

  const sig = holder.sig;
  if (typeof sig !== "string" || sig.length === 0) {
    throw new Error("Missing signature (expected data.sig or sig)");
  }
  const kid = typeof holder.kid === "string" ? holder.kid : undefined;

  return { trust: trust as TrustProfile, sig, kid , pqSig: typeof holder.pqSig === "string" ? (holder.pqSig as string) : undefined, pqKid: typeof holder.pqKid === "string" ? (holder.pqKid as string) : undefined };
}

async function checkTrustSignature(
  trust: TrustProfile,
  sig: string,
  keyJwk?: JsonWebKey,
  kid?: string
): Promise<CheckResult> {
  if (!subtle) {
    return { passed: false, reason: "Web Crypto API not available" };
  }
  const problem = kidProblem(kid, TRUST_KIDS, "trust profile");
  if (problem) return { passed: false, reason: problem };

  try {
    const key = await subtle.importKey(
      "jwk",
      keyJwk || PUBLIC_KEY_JWK,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    // Reconstruct the exact bytes signed server-side, selected by kid.
    // v1 signs the object as-is (insertion order), so it is stringified
    // directly rather than rebuilt field by field.
    const payload =
      kid === V2_TRUST_KID
        ? V2_TRUST_DOMAIN + "\n" + canonicalize(trust)
        : (assertDepth(trust), JSON.stringify(trust));

    const payloadBytes = new TextEncoder().encode(payload);
    const sigBytes = base64ToBytes(sig);

    const valid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes.buffer as ArrayBuffer,
      payloadBytes
    );

    return valid
      ? { passed: true }
      : { passed: false, reason: "Signature does not match trust profile" };
  } catch (e) {
    return {
      passed: false,
      reason: `Signature verification error: ${(e as Error).message}`,
    };
  }
}

// Same clock-skew allowance as the attestation path (options.clockSkew, Section 9.4).
function checkTrustFreshness(trust: TrustProfile, maxAge: number | undefined, skewMs: number): CheckResult {
  if (maxAge === undefined) {
    return { passed: true, reason: "Freshness check skipped (no maxAge)" };
  }
  const now = Date.now();
  const maxAgeMs = maxAge * 1000;
  const limitMs = maxAgeMs + skewMs;
  const limitText = `max: ${maxAge}s + ${skewMs / 1000}s clock skew`;

  // 1) Top-level profile freshness (when the profile was assembled).
  const profiledTs = new Date(String(trust.profiledAt)).getTime();
  if (isNaN(profiledTs)) {
    return { passed: false, reason: "Invalid profiledAt timestamp" };
  }
  if (now - profiledTs > limitMs) {
    return {
      passed: false,
      reason: `Profile is ${Math.round((now - profiledTs) / 1000)}s old (${limitText})`,
    };
  }

  // 2) Per-check on-chain freshness. Each dimension's checks carry a
  // blockTimestamp for chains that expose one; a stale on-chain read fails even
  // when profiledAt is fresh. Checks without a blockTimestamp (e.g. XRPL, which
  // uses ledgerIndex, or a check marked evaluated: false, which carries no anchor
  // at all; spec Section 11.3) are skipped, matching the attestation freshness path.
  const dims = trust.dimensions;
  if (dims && typeof dims === "object") {
    for (const dimName of Object.keys(dims as Record<string, unknown>)) {
      const dim = (dims as Record<string, unknown>)[dimName];
      const checks =
        dim && typeof dim === "object" ? (dim as Record<string, unknown>).checks : undefined;
      if (!Array.isArray(checks)) continue;
      for (const c of checks) {
        const bts =
          c && typeof c === "object" ? (c as Record<string, unknown>).blockTimestamp : undefined;
        if (typeof bts !== "string") continue;
        const t = new Date(bts).getTime();
        if (isNaN(t)) continue;
        if (now - t > limitMs) {
          return {
            passed: false,
            reason: `Dimension "${dimName}" on-chain data is ${Math.round((now - t) / 1000)}s old (${limitText})`,
          };
        }
      }
    }
  }

  return { passed: true };
}

function checkTrustExpiry(expiresAt: string, skewMs: number): CheckResult {
  const ts = new Date(expiresAt).getTime();
  if (isNaN(ts)) {
    return { passed: false, reason: "Invalid expiresAt timestamp" };
  }
  if (Date.now() > ts + skewMs) {
    return { passed: false, reason: "Trust profile has expired" };
  }
  return { passed: true };
}

/**
 * Verify an InsumerAPI trust profile from POST /v1/trust.
 *
 * Reports four independent verdicts:
 * 1. **Signature** — ECDSA P-256 over the scheme selected by `kid`
 * 2. **Freshness** — profiledAt AND per-dimension on-chain blockTimestamp age vs
 *    caller-defined maxAge (optional)
 * 3. **Expiry** — whether the profile window has elapsed
 * 4. **Post-quantum companion** — verified / refuted / absent / unverifiable (spec Check 6)
 *
 * Rejects any object that is not shaped like a trust profile (guards the shared
 * v1 kid). On success, returns the verified profile as `result.trust` — render
 * that, gated on `result.valid`, not your own copy of the response.
 *
 * Pass the response object as parsed from the wire. Do not rebuild the
 * `trust` object: the v1 scheme signs bare `JSON.stringify` output, so
 * changing key order changes the signed bytes.
 *
 * For POST /v1/trust/batch, call this once per entry (`data.results[i]`).
 *
 * @param response Full API response object, or an inner { trust, sig, kid }
 * @param options Optional configuration: maxAge (seconds), clockSkew (seconds, default 60), jwksUrl, jwks (a saved key set; nothing fetched)
 */
export async function verifyTrustProfile(
  response: unknown,
  options?: VerifyOptions
): Promise<TrustVerifyResult> {
  let parsed: ParsedTrustResponse;
  try {
    parsed = parseTrustResponse(response);
  } catch (e) {
    const reason = (e as Error).message;
    return {
      valid: false,
      checks: {
        signature: { passed: false, reason },
        freshness: { passed: false, reason: "Skipped (parse failed)" },
        expiry: { passed: false, reason: "Skipped (parse failed)" },
        pq: { status: "unverifiable", passed: false, reason: "Skipped (parse failed)" },
      },
    };
  }

  const { trust, sig, kid, pqSig, pqKid } = parsed;

  let keyJwk: JsonWebKey | undefined;
  if (options?.jwks || options?.jwksUrl) {
    try {
      keyJwk = await fetchJwksKey(options, kid);
    } catch (e) {
      return {
        valid: false,
        trust,
        checks: {
          signature: { passed: false, reason: `JWKS fetch error: ${(e as Error).message}` },
          freshness: { passed: false, reason: "Skipped (JWKS fetch failed)" },
          expiry: { passed: false, reason: "Skipped (JWKS fetch failed)" },
          pq: { status: "unverifiable", passed: false, reason: "Skipped (JWKS fetch failed)" },
        },
      };
    }
  }

  const skewMs = clockSkewMs(options);
  const signature = await checkTrustSignature(trust, sig, keyJwk, kid);
  const freshness = checkTrustFreshness(trust, options?.maxAge, skewMs);
  const expiry = checkTrustExpiry(String(trust.expiresAt), skewMs);
  // Post-quantum companion over the same classical trust preimage the kid selects,
  // under the trust domain tag; reported as its own verdict (see checkPqSignature).
  const pq =
    unknownClassicalKidPq(kid, pqSig, pqKid, options, String(trust.profiledAt ?? "")) ??
    (await checkPqSignature(
      PQ_TRUST_DOMAIN,
      kid === V2_TRUST_KID
        ? V2_TRUST_DOMAIN + "\n" + canonicalize(trust)
        : (assertDepth(trust), JSON.stringify(trust)),
      pqSig,
      pqKid,
      options,
      trust.profiledAt
    ));

  return {
    valid: signature.passed && freshness.passed && expiry.passed && pq.passed,
    trust,
    checks: { signature, freshness, expiry, pq },
  };
}
