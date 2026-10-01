"""Verification of InsumerAPI attestations and trust profiles.

Mirrors the JavaScript reference verifier check for check. Both accept the
same inputs, report the same independent verdicts, and pass the same
published test vectors, so a verdict from one can be reproduced with the other.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, TypeVar

from . import _keys
from ._jsjson import (
    CanonicalDepthError,
    assert_depth,
    canonicalize,
    first_claim_difference,
    js_stringify,
    v1_condition_canonical,
)
from ._keys import (
    ATTEST_KIDS,
    KNOWN_CLASSICAL_KIDS,
    KNOWN_PQ_KIDS,
    PQ_UNAVAILABLE_REASON,
    PUBLIC_KEY_JWK,
    TRUST_KIDS,
    b64_decode,
    b64url_decode,
    b64url_decode_text,
)
from ._time import iso_from_ms, now_ms, parse_time_ms

# ── Clock tolerances ─────────────────────────────────────────────────

#: Default clock-skew allowance for the freshness and expiry checks, in seconds
#: (spec Section 9.4 RECOMMENDS 60). Overridden per call by ``clock_skew``.
DEFAULT_CLOCK_SKEW_SECONDS = 60

#: Grace on the expiresAt-to-attestedAt binding (spec Check 4), in
#: milliseconds. An honest expiresAt is exactly attestedAt plus the issuance
#: window; this absorbs rounding at that boundary. It is a verifier tolerance
#: the spec permits (up to 60 seconds), fixed rather than configurable, and
#: separate from ``clock_skew``.
EXPIRY_BINDING_GRACE_MS = 60 * 1000

# Signing domains. The kid on the response selects the scheme: insumer-attest-v1
# (bare JSON, frozen) or insumer-attest-v2 (domain tag + canonical JSON).
V2_ATTEST_DOMAIN = "insumer.attestation.v2"
V2_TRUST_DOMAIN = "insumer.trust.v2"
V2_TRUST_KID = "insumer-trust-v2"
PQ_ATTEST_DOMAIN = "insumer.attestation.pq1"
PQ_TRUST_DOMAIN = "insumer.trust.pq1"

Check = Dict[str, Any]
T = TypeVar("T")

_OPTION_KEYS = frozenset(
    {"max_age", "clock_skew", "jwks_url", "jwks", "mode", "pq_required_from", "pq_activated_at", "pq_jwt", "_fetch_json"}
)


def _options(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    unknown = set(kwargs) - _OPTION_KEYS
    if unknown:
        raise TypeError(f"unknown option(s): {', '.join(sorted(unknown))}")
    return {k: v for k, v in kwargs.items() if v is not None}


def _clock_skew_ms(options: Dict[str, Any]) -> int:
    s = options.get("clock_skew")
    if isinstance(s, bool) or not isinstance(s, (int, float)) or s != s:
        seconds: float = DEFAULT_CLOCK_SKEW_SECONDS
    else:
        seconds = max(0.0, float(s))
    return int(seconds * 1000)


def _failed(reason: str) -> Check:
    return {"passed": False, "reason": reason}


def _failed_pq(reason: str) -> Check:
    return {"status": "unverifiable", "passed": False, "reason": reason}


def _guarded(thunk: Callable[[], T], on_failure: Callable[[str], T]) -> T:
    """Runs one check so that a raised error becomes a FAILED CHECK, never an escape.

    The thunk is called in here so that an argument which raises while being
    built, such as a signing preimage from a hostile artifact, is caught too.
    """
    try:
        return thunk()
    except (CanonicalDepthError, RecursionError) as e:
        return on_failure(f"Refused: artifact too deeply nested to verify ({e})")
    except Exception as e:  # noqa: BLE001 (any failure is a verdict)
        return on_failure(f"Verification error: {e}")


# ── Post-quantum companion (ML-DSA-65, RFC 9964) ─────────────────────
#
# The companion is ADDITIVE: pqSig signs "insumer.attestation.pq1" + "\n" + the
# exact classical preimage the classical kid selects; pqJwt is a separate
# compact JWS (alg "ML-DSA-65") over the same claims as jwt. The PQ public key
# is an RFC 9964 JWK (kty "AKP", pub) in the same JWKS, resolved by pqKid.


def _pq_policy(status: str, options: Dict[str, Any], attested_at: Optional[str]) -> Dict[str, Any]:
    existed: Optional[bool] = None
    activated = options.get("pq_activated_at")
    if activated is not None and attested_at:
        act = parse_time_ms(activated)
        at = parse_time_ms(attested_at)
        if act is not None and at is not None:
            existed = at >= act
    if status == "refuted":
        return {"passed": False, "existedAtIssuance": existed}
    if status == "verified":
        return {"passed": True, "existedAtIssuance": existed}
    # absent / unverifiable: required only in access mode once the verifier's own date has passed
    mode = options.get("mode", "access")
    required_from = options.get("pq_required_from")
    if mode == "evidence" or required_from is None:
        return {"passed": True, "existedAtIssuance": existed}
    from_ms = parse_time_ms(required_from)
    required = from_ms is not None and now_ms() >= from_ms
    return {"passed": not required, "existedAtIssuance": existed}


def _pq_result(status: str, options: Dict[str, Any], attested_at: Optional[str], kid: Optional[str] = None, reason: Optional[str] = None) -> Check:
    pol = _pq_policy(status, options, attested_at)
    out: Check = {"status": status, "passed": pol["passed"]}
    if kid is not None:
        out["kid"] = kid
    if pol["existedAtIssuance"] is not None:
        out["existedAtIssuance"] = pol["existedAtIssuance"]
    if reason is not None:
        out["reason"] = reason
    return out


def _absent_reason(options: Dict[str, Any], passed: bool, default: str) -> str:
    if passed:
        return default
    return f"Post-quantum companion required from {options.get('pq_required_from')} and absent"


def _check_pq_signature(
    domain: str,
    classical_preimage: Callable[[], str],
    pq_sig: Optional[str],
    pq_kid: Optional[str],
    options: Dict[str, Any],
    attested_at: Optional[str],
) -> Check:
    # classical_preimage is a thunk: building the preimage canonicalizes the
    # artifact, and an artifact with no companion must never be canonicalized
    # on the companion's behalf.
    if not pq_sig:
        pol = _pq_policy("absent", options, attested_at)
        return _pq_result("absent", options, attested_at, reason=_absent_reason(options, pol["passed"], "No post-quantum companion on this response"))
    if not pq_kid:
        return _pq_result("unverifiable", options, attested_at, reason="pqSig present without pqKid")
    expected_pq_kid = "insumer-trust-pq1" if domain == PQ_TRUST_DOMAIN else "insumer-attest-pq1"
    if pq_kid in KNOWN_PQ_KIDS and pq_kid != expected_pq_kid:
        return _pq_result("unverifiable", options, attested_at, kid=pq_kid, reason=f'pqKid "{pq_kid}" does not name this artifact type (expected {expected_pq_kid})')
    ml_dsa = _keys.load_ml_dsa()
    if ml_dsa is None:
        return _pq_result("unverifiable", options, attested_at, kid=pq_kid, reason=PQ_UNAVAILABLE_REASON)
    try:
        public_key = _keys.fetch_pq_key(options, pq_kid)
    except Exception as e:  # noqa: BLE001
        return _pq_result("unverifiable", options, attested_at, kid=pq_kid, reason=str(e))
    preimage = classical_preimage()  # may raise on a hostile artifact: the caller's guard reports it
    try:
        message = (domain + "\n" + preimage).encode("utf-8")
        ok = ml_dsa(b64_decode(pq_sig), message, public_key)
    except Exception as e:  # noqa: BLE001
        return _pq_result("refuted", options, attested_at, kid=pq_kid, reason=f"Post-quantum verification error: {e}")
    if ok:
        return _pq_result("verified", options, attested_at, kid=pq_kid)
    return _pq_result("refuted", options, attested_at, kid=pq_kid, reason="Post-quantum companion does not verify (tampered payload or wrong key)")


def _unknown_classical_kid_pq(kid: Optional[str], pq_sig: Optional[str], pq_kid: Optional[str], options: Dict[str, Any], at: Optional[str]) -> Optional[Check]:
    """A companion under a classical kid this verifier has never met is unverifiable.

    The companion signs the exact classical preimage the classical kid selects.
    A kid this verifier does not know selects no preimage, so the companion
    cannot be evaluated; substituting another era's preimage could only produce
    a false "refuted". A KNOWN kid that names the other artifact type is a
    relabelled artifact, not a rotation, and keeps its refuted verdict.
    """
    if not pq_sig:
        return None
    if kid is not None and kid in KNOWN_CLASSICAL_KIDS:
        return None
    shown = "(absent)" if kid is None else f'"{kid}"'
    return _pq_result("unverifiable", options, at, kid=pq_kid, reason=f"Classical kid {shown} is unknown to this verifier, so the preimage the companion signs cannot be reconstructed")


# ── JWT parsing ──────────────────────────────────────────────────────


class _Jwt:
    __slots__ = ("header", "payload", "header_b64", "payload_b64", "signature")

    def __init__(self, header: Dict[str, Any], payload: Dict[str, Any], header_b64: str, payload_b64: str, signature: bytes) -> None:
        self.header = header
        self.payload = payload
        self.header_b64 = header_b64
        self.payload_b64 = payload_b64
        self.signature = signature


def _parse_jwt(token: str) -> _Jwt:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 dot-separated segments")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(b64url_decode_text(header_b64))
    except Exception:  # noqa: BLE001
        raise ValueError("Invalid JWT: malformed header") from None
    try:
        payload = json.loads(b64url_decode_text(payload_b64))
    except Exception:  # noqa: BLE001
        raise ValueError("Invalid JWT: malformed payload") from None
    if not isinstance(header, dict):
        raise ValueError("Invalid JWT: header is not a JSON object")
    if not isinstance(payload, dict):
        raise ValueError("Invalid JWT: payload is not a JSON object")
    return _Jwt(header, payload, header_b64, payload_b64, b64url_decode(sig_b64))


def _check_pq_jwt(pq_jwt: Optional[str], classical: Optional[_Jwt], options: Dict[str, Any], attested_at: Optional[str]) -> Check:
    """pqJwt: compact JWS, alg ML-DSA-65, same claims as the ES256 JWT.

    Verified over its own header.payload bytes, then bound to the classical JWT
    by the full claim set, so the companion vouches for every claim a relying
    party reads from the ES256 JWT and cannot be transplanted from another
    artifact.
    """
    if not pq_jwt:
        pol = _pq_policy("absent", options, attested_at)
        return _pq_result("absent", options, attested_at, reason=_absent_reason(options, pol["passed"], "No pqJwt was supplied to this call; pass pq_jwt (a bare token string cannot carry its companion)"))
    try:
        parts = _parse_jwt(pq_jwt)
    except Exception as e:  # noqa: BLE001
        return _pq_result("refuted", options, attested_at, reason=f"pqJwt parse error: {e}")
    pq_kid = parts.header.get("kid")
    if parts.header.get("alg") != "ML-DSA-65" or not isinstance(pq_kid, str) or not pq_kid:
        return _pq_result("refuted", options, attested_at, kid=pq_kid if isinstance(pq_kid, str) else None, reason=f"pqJwt header must carry alg ML-DSA-65 and a kid (got alg {parts.header.get('alg')})")
    if pq_kid in KNOWN_PQ_KIDS and pq_kid != "insumer-attest-pq1":
        return _pq_result("unverifiable", options, attested_at, kid=pq_kid, reason=f'pqJwt kid "{pq_kid}" does not name an attestation companion (expected insumer-attest-pq1)')
    ml_dsa = _keys.load_ml_dsa()
    if ml_dsa is None:
        return _pq_result("unverifiable", options, attested_at, kid=pq_kid, reason=PQ_UNAVAILABLE_REASON)
    try:
        public_key = _keys.fetch_pq_key(options, pq_kid)
    except Exception as e:  # noqa: BLE001
        return _pq_result("unverifiable", options, attested_at, kid=pq_kid, reason=str(e))
    signing_input = f"{parts.header_b64}.{parts.payload_b64}".encode("utf-8")
    if not ml_dsa(parts.signature, signing_input, public_key):
        return _pq_result("refuted", options, attested_at, kid=pq_kid, reason="pqJwt signature does not verify")
    if classical is not None and parts.payload_b64 != classical.payload_b64:
        # Nesting past the bound cannot be compared, and what cannot be shown equal is not bound.
        try:
            claim = first_claim_difference(parts.payload, classical.payload)
        except CanonicalDepthError:
            claim = "(nested too deeply to compare)"
        if claim is not None:
            return _pq_result("refuted", options, attested_at, kid=pq_kid, reason=f'pqJwt claim "{claim}" differs from the ES256 JWT')
    return _pq_result("verified", options, attested_at, kid=pq_kid)


# ── Response parsing ─────────────────────────────────────────────────


def _parse_response(response: Any) -> Dict[str, Any]:
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, dict):
        raise ValueError("Invalid response: missing data object")
    attestation = data.get("attestation")
    sig = data.get("sig")
    if not isinstance(attestation, dict):
        raise ValueError("Invalid response: missing data.attestation")
    if not isinstance(sig, str) or not sig:
        raise ValueError("Invalid response: missing data.sig")
    if not isinstance(attestation.get("id"), str):
        raise ValueError("Invalid response: missing attestation.id")
    if not isinstance(attestation.get("pass"), bool):
        raise ValueError("Invalid response: missing attestation.pass")
    if not isinstance(attestation.get("results"), list):
        raise ValueError("Invalid response: missing attestation.results")
    if not isinstance(attestation.get("attestedAt"), str):
        raise ValueError("Invalid response: missing attestation.attestedAt")
    if not isinstance(attestation.get("expiresAt"), str):
        raise ValueError("Invalid response: missing attestation.expiresAt")
    return {
        "attestation": attestation,
        "sig": sig,
        "kid": data.get("kid") if isinstance(data.get("kid"), str) else None,
        "pqSig": data.get("pqSig") if isinstance(data.get("pqSig"), str) else None,
        "pqKid": data.get("pqKid") if isinstance(data.get("pqKid"), str) else None,
        "pqJwt": data.get("pqJwt") if isinstance(data.get("pqJwt"), str) else None,
    }


def _js_falsy(value: Any) -> bool:
    """JavaScript's ``!value`` on a JSON value: null, false, 0 and the empty string are falsy."""
    return value is None or value is False or value == "" or (isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0)


def _kid_problem(kid: Optional[str], allowed: frozenset, artifact: str) -> Optional[str]:
    if not kid:
        return f"Response carries no kid; the signing key and scheme cannot be selected ({artifact})"
    if kid not in allowed:
        return f'kid "{kid}" does not sign {artifact}s'
    return None


# ── Preimages ────────────────────────────────────────────────────────


def classical_attest_preimage(attestation: Dict[str, Any], kid: Optional[str]) -> str:
    """The exact bytes the server signed, selected by scheme (kid).

    v1: bare ``JSON.stringify({ id, pass, results, attestedAt })`` in that
    insertion order, results exactly as received. v2: the domain tag, a
    newline, and canonical JSON of ``{ v: 2, id, pass, results, attestedAt }``.
    """
    body = {"id": attestation["id"], "pass": attestation["pass"], "results": attestation["results"], "attestedAt": attestation["attestedAt"]}
    if kid == "insumer-attest-v2":
        return V2_ATTEST_DOMAIN + "\n" + canonicalize({"v": 2, **body})
    assert_depth(attestation["results"])
    return js_stringify(body)


def classical_trust_preimage(trust: Dict[str, Any], kid: Optional[str]) -> str:
    """v1: ``JSON.stringify(trust)`` as parsed; v2: the trust domain tag plus canonical JSON of the whole object."""
    if kid == V2_TRUST_KID:
        return V2_TRUST_DOMAIN + "\n" + canonicalize(trust)
    assert_depth(trust)
    return js_stringify(trust)


def condition_hash(evaluated_condition: Dict[str, Any], kid: Optional[str]) -> str:
    """``"0x" + hex(SHA-256(canonical JSON of evaluatedCondition))`` per the scheme the kid selects."""
    import hashlib

    canonical = canonicalize(evaluated_condition) if kid == "insumer-attest-v2" else v1_condition_canonical(evaluated_condition)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Checks ───────────────────────────────────────────────────────────


def _check_signature(attestation: Dict[str, Any], sig: str, key_jwk: Optional[Dict[str, str]], kid: Optional[str]) -> Check:
    problem = _kid_problem(kid, ATTEST_KIDS, "attestation")
    if problem:
        return _failed(problem)
    try:
        preimage = classical_attest_preimage(attestation, kid)
        ok = _keys.ecdsa_verify(key_jwk or PUBLIC_KEY_JWK, b64_decode(sig), preimage.encode("utf-8"))
    except (CanonicalDepthError, RecursionError):
        raise
    except Exception as e:  # noqa: BLE001
        return _failed(f"Signature verification error: {e}")
    return {"passed": True} if ok else _failed("Signature does not match payload")


def _check_jwt_signature(jwt: _Jwt, key_jwk: Optional[Dict[str, str]]) -> Check:
    problem = _kid_problem(jwt.header.get("kid") if isinstance(jwt.header.get("kid"), str) else None, ATTEST_KIDS, "attestation")
    if problem:
        return _failed(problem)
    if jwt.header.get("alg") != "ES256":
        return _failed(f"Unsupported JWT algorithm: {jwt.header.get('alg')}")
    try:
        signing_input = f"{jwt.header_b64}.{jwt.payload_b64}".encode("utf-8")
        ok = _keys.ecdsa_verify(key_jwk or PUBLIC_KEY_JWK, jwt.signature, signing_input, accept_der=True)
    except Exception as e:  # noqa: BLE001
        return _failed(f"JWT signature verification error: {e}")
    return {"passed": True} if ok else _failed("JWT signature does not match payload")


def _check_condition_hashes(results: List[Any], kid: Optional[str]) -> Check:
    failures: List[int] = []
    for i, r in enumerate(results):
        # Every result MUST carry both (spec Section 8); a result that lacks either
        # cannot be recomputed and is recorded as a failure rather than passed over.
        ec = r.get("evaluatedCondition") if isinstance(r, dict) else None
        if not isinstance(r, dict) or _js_falsy(ec) or _js_falsy(r.get("conditionHash")):
            failures.append(i)
            continue
        # A condition that is not an object still goes through canonicalization, as it
        # does in the reference verifier: a hostile shape is refused by the depth bound
        # (and reported as such), never quietly counted as a mismatch.
        if condition_hash(ec, kid) != r["conditionHash"]:
            failures.append(i)
    if failures:
        return {"passed": False, "failures": failures, "reason": "Condition hash mismatch at result index(es): " + ", ".join(str(i) for i in failures)}
    return {"passed": True}


def _check_freshness(results: List[Any], max_age: Optional[float], skew_ms: int) -> Check:
    # Freshness (spec Check 3): blockTimestamp age against the caller's maxAge,
    # with the clock-skew allowance added to the limit.
    if max_age is None:
        return {"passed": True, "reason": "Freshness check skipped (no maxAge)"}
    now = now_ms()
    max_age_ms = max_age * 1000
    for i, r in enumerate(results):
        if not isinstance(r, dict):
            continue
        bts = r.get("blockTimestamp")
        if not bts:
            continue  # some chains lack blockTimestamp
        t = parse_time_ms(bts)
        if t is None:
            continue
        age = now - t
        if age > max_age_ms + skew_ms:
            return _failed(f"Result {i} blockTimestamp is {round(age / 1000)}s old (max: {max_age:g}s + {skew_ms / 1000:g}s clock skew)")
    return {"passed": True}


def _check_expiry(expires_at: str, skew_ms: int, attested_at: Optional[str] = None, results: Optional[List[Any]] = None) -> Check:
    # Expiry (spec Check 4). Step 1 binds the unsigned expiresAt to the signed
    # attestedAt under EXPIRY_BINDING_GRACE_MS; step 2 compares expiresAt to the
    # clock, with the clock-skew allowance.
    ts = parse_time_ms(expires_at)
    if ts is None:
        return _failed("Invalid expiresAt timestamp")
    if attested_at:
        at = parse_time_ms(attested_at)
        if at is not None:
            has_delegation = bool(results) and any(
                isinstance(r, dict) and isinstance(r.get("evaluatedCondition"), dict) and r["evaluatedCondition"].get("type") == "erc7710_delegation"
                for r in results  # type: ignore[union-attr]
            )
            max_window_ms = (5 if has_delegation else 30) * 60 * 1000
            if ts - at > max_window_ms + EXPIRY_BINDING_GRACE_MS:
                return _failed("expiresAt exceeds the signed issuance window (attestedAt + max); treated as tampered")
    if now_ms() > ts + skew_ms:
        return _failed("Attestation has expired")
    return {"passed": True}


# ── JWT verification path ────────────────────────────────────────────


def _check_embedded_jwt(
    token: Any,
    pq_jwt: Any,
    attestation: Dict[str, Any],
    response_kid: Optional[str],
    key_jwk: Optional[Dict[str, str]],
    key_problem: Optional[str],
    options: Dict[str, Any],
) -> Check:
    # A format:"jwt" response carries the tokens BESIDE the attestation. They are
    # verified here as well and bound to the attestation already verified.
    if not isinstance(token, str):
        return _failed("Response carries data.pqJwt without a data.jwt string" if isinstance(pq_jwt, str) else "data.jwt is not a string")
    try:
        jwt = _parse_jwt(token)
    except Exception as e:  # noqa: BLE001
        return _failed(f"data.jwt: {e}")
    if jwt.header.get("kid") != response_kid:
        return _failed(f'data.jwt names kid "{jwt.header.get("kid")}" but the response is signed under "{response_kid}"')
    # From here the token is parsed and names this response's kid, so the
    # companion has a classical token to be bound to and its verdict is
    # reported whatever a later check decides.
    pq = _check_pq_jwt(pq_jwt if isinstance(pq_jwt, str) else None, jwt, options, attestation.get("attestedAt"))

    def fail(reason: str) -> Check:
        return {"passed": False, "pq": pq, "reason": reason}

    if key_problem:
        return fail(f"data.jwt signature: {key_problem}")
    signature = _check_jwt_signature(jwt, key_jwk)
    if not signature["passed"]:
        return fail(f"data.jwt signature: {signature.get('reason', 'does not verify')}")
    p = jwt.payload
    exp_ms = parse_time_ms(attestation["expiresAt"])
    exp_seconds = exp_ms // 1000 if exp_ms is not None else None
    for name, a, b in (("jti", p.get("jti"), attestation["id"]), ("pass", p.get("pass"), attestation["pass"]), ("results", p.get("results"), attestation["results"]), ("exp", p.get("exp"), exp_seconds)):
        if name not in p:
            return fail(f'data.jwt claim "{name}" differs from the attestation in the same response')
        d = first_claim_difference(a, b, name)
        if d is not None:
            return fail(f'data.jwt claim "{d}" differs from the attestation in the same response')
    hashes = _check_condition_hashes(p.get("results") or [], response_kid)
    if not hashes["passed"]:
        return fail(f"data.jwt condition hashes: {hashes.get('reason', 'failed')}")
    if not pq["passed"]:
        return fail(f"data.pqJwt: {pq.get('reason', pq['status'])}")
    return {"passed": True, "pq": pq}


def _verify_jwt(token: str, options: Dict[str, Any]) -> Dict[str, Any]:
    try:
        jwt = _parse_jwt(token)
    except Exception as e:  # noqa: BLE001
        reason = f"JWT parse error: {e}"
        return {
            "valid": False,
            "checks": {
                "signature": _failed(reason),
                "conditionHashes": _failed("Skipped (JWT parse failed)"),
                "freshness": _failed("Skipped (JWT parse failed)"),
                "expiry": _failed("Skipped (JWT parse failed)"),
                "pq": _failed_pq("Skipped (JWT parse failed)"),
            },
        }
    p = jwt.payload
    kid = jwt.header.get("kid") if isinstance(jwt.header.get("kid"), str) else None
    # A kid that selects no key is the signature verdict's failure, not everyone's.
    key_jwk, key_problem = _keys.select_jwks_key(options, kid)
    results = p.get("results") or []
    if not isinstance(results, list):
        results = []
    exp = p.get("exp")
    expires_at = iso_from_ms(int(exp * 1000)) if isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp else ""
    iat = p.get("iat")
    attested_at = iso_from_ms(int(iat * 1000)) if isinstance(iat, (int, float)) and not isinstance(iat, bool) and iat else None
    skew_ms = _clock_skew_ms(options)
    signature = _guarded(lambda: _failed(key_problem) if key_problem else _check_jwt_signature(jwt, key_jwk), _failed)
    condition_hashes = _guarded(lambda: _check_condition_hashes(results, kid), _failed)
    freshness = _guarded(lambda: _check_freshness(results, options.get("max_age"), skew_ms), _failed)
    expiry = _guarded(lambda: _check_expiry(expires_at, skew_ms), _failed)
    pq = _guarded(lambda: _check_pq_jwt(options.get("pq_jwt"), jwt, options, attested_at), _failed_pq)
    valid = all(c["passed"] for c in (signature, condition_hashes, freshness, expiry, pq))
    return {"valid": valid, "checks": {"signature": signature, "conditionHashes": condition_hashes, "freshness": freshness, "expiry": expiry, "pq": pq}}


# ── Public API ───────────────────────────────────────────────────────


def verify_attestation(response: Any, **options: Any) -> Dict[str, Any]:
    """Verify an InsumerAPI attestation response.

    ``response`` is either the full API response object (as parsed from the
    wire) or a JWT string from ``format: "jwt"``. Both report the same five
    independent verdicts under ``checks``: ``signature``, ``conditionHashes``,
    ``freshness``, ``expiry`` and ``pq`` (the post-quantum companion, with a
    ``status`` of ``verified``, ``refuted``, ``absent`` or ``unverifiable``).
    A response object carrying ``data.jwt`` beside ``data.attestation`` also
    reports ``checks.jwt``. ``valid`` is true only when every check passed.

    Options (all keyword-only): ``max_age`` (seconds), ``clock_skew`` (seconds,
    default 60), ``jwks_url``, ``jwks`` (a saved key set; nothing is fetched),
    ``mode`` (``"access"`` or ``"evidence"``), ``pq_required_from``,
    ``pq_activated_at`` and ``pq_jwt`` (the companion for a bare JWT string).

    Raises ``ValueError`` when the object is not an attestation response at all
    (for example the inner ``data`` object instead of the envelope).
    """
    opts = _options(options)
    if isinstance(response, str):
        return _verify_jwt(response, opts)
    data = response.get("data") if isinstance(response, dict) else None
    # An object carrying data.jwt but no data.attestation is the JWT-format
    # envelope: route it to the JWT path with its companion attached.
    if isinstance(data, dict) and isinstance(data.get("jwt"), str) and data.get("attestation") is None:
        routed = dict(opts)
        if isinstance(data.get("pqJwt"), str):
            routed["pq_jwt"] = data["pqJwt"]
        return _verify_jwt(data["jwt"], routed)

    parsed = _parse_response(response)
    attestation, sig, kid, pq_sig, pq_kid = parsed["attestation"], parsed["sig"], parsed["kid"], parsed["pqSig"], parsed["pqKid"]
    has_embedded_jwt = isinstance(data, dict) and (data.get("jwt") is not None or data.get("pqJwt") is not None)

    key_jwk: Optional[Dict[str, str]] = None
    key_problem: Optional[str] = None
    if opts.get("jwks") is not None or opts.get("jwks_url"):
        key_jwk, key_problem = _keys.select_jwks_key(opts, kid)

    skew_ms = _clock_skew_ms(opts)
    attested_at = attestation["attestedAt"]
    signature = _guarded(lambda: _failed(key_problem) if key_problem else _check_signature(attestation, sig, key_jwk, kid), _failed)
    condition_hashes = _guarded(lambda: _check_condition_hashes(attestation["results"], kid), _failed)
    freshness = _guarded(lambda: _check_freshness(attestation["results"], opts.get("max_age"), skew_ms), _failed)
    expiry = _guarded(lambda: _check_expiry(attestation["expiresAt"], skew_ms, attested_at, attestation["results"]), _failed)
    pq = _guarded(
        lambda: _unknown_classical_kid_pq(kid, pq_sig, pq_kid, opts, attested_at)
        or _check_pq_signature(PQ_ATTEST_DOMAIN, lambda: classical_attest_preimage(attestation, kid), pq_sig, pq_kid, opts, attested_at),
        _failed_pq,
    )
    checks: Dict[str, Any] = {"signature": signature, "conditionHashes": condition_hashes, "freshness": freshness, "expiry": expiry, "pq": pq}
    if has_embedded_jwt:
        checks["jwt"] = _guarded(lambda: _check_embedded_jwt(data.get("jwt"), data.get("pqJwt"), attestation, kid, key_jwk, key_problem, opts), _failed)  # type: ignore[union-attr]
    valid = all(c["passed"] for c in checks.values())
    return {"valid": valid, "checks": checks}


# ── Trust profile verification ───────────────────────────────────────


def _parse_trust_response(response: Any) -> Dict[str, Any]:
    if not isinstance(response, dict):
        raise ValueError("Response must be an object")
    holder: Dict[str, Any] = response
    data = response.get("data")
    if isinstance(data, dict) and data.get("trust"):
        holder = data
    trust = holder.get("trust")
    if not isinstance(trust, dict):
        raise ValueError("Missing trust profile (expected data.trust or trust)")
    # Structural gate. The v1 scheme signs a bare-JSON preimage with no type
    # binding and one kid covers every v1 artifact, so a non-trust object signed
    # by the same key could otherwise satisfy a trust-profile check.
    looks_like_trust = (
        isinstance(trust.get("wallet"), str)
        and isinstance(trust.get("profiledAt"), str)
        and isinstance(trust.get("expiresAt"), str)
        and isinstance(trust.get("dimensions"), (dict, list))
        and isinstance(trust.get("summary"), (dict, list))
    )
    if not looks_like_trust:
        raise ValueError("Object is not a trust profile (expected wallet, dimensions, summary, profiledAt, expiresAt)")
    sig = holder.get("sig")
    if not isinstance(sig, str) or not sig:
        raise ValueError("Missing signature (expected data.sig or sig)")
    return {
        "trust": trust,
        "sig": sig,
        "kid": holder.get("kid") if isinstance(holder.get("kid"), str) else None,
        "pqSig": holder.get("pqSig") if isinstance(holder.get("pqSig"), str) else None,
        "pqKid": holder.get("pqKid") if isinstance(holder.get("pqKid"), str) else None,
    }


def _check_trust_signature(trust: Dict[str, Any], sig: str, key_jwk: Optional[Dict[str, str]], kid: Optional[str]) -> Check:
    problem = _kid_problem(kid, TRUST_KIDS, "trust profile")
    if problem:
        return _failed(problem)
    try:
        preimage = classical_trust_preimage(trust, kid)
        ok = _keys.ecdsa_verify(key_jwk or PUBLIC_KEY_JWK, b64_decode(sig), preimage.encode("utf-8"))
    except (CanonicalDepthError, RecursionError):
        raise
    except Exception as e:  # noqa: BLE001
        return _failed(f"Signature verification error: {e}")
    return {"passed": True} if ok else _failed("Signature does not match trust profile")


def _check_trust_freshness(trust: Dict[str, Any], max_age: Optional[float], skew_ms: int) -> Check:
    if max_age is None:
        return {"passed": True, "reason": "Freshness check skipped (no maxAge)"}
    now = now_ms()
    limit_ms = max_age * 1000 + skew_ms
    limit_text = f"max: {max_age:g}s + {skew_ms / 1000:g}s clock skew"
    profiled = parse_time_ms(str(trust.get("profiledAt")))
    if profiled is None:
        return _failed("Invalid profiledAt timestamp")
    if now - profiled > limit_ms:
        return _failed(f"Profile is {round((now - profiled) / 1000)}s old ({limit_text})")
    # Per-check on-chain freshness. Checks without a blockTimestamp (XRPL, or a
    # check marked evaluated: false, which carries no anchor) are skipped.
    dims = trust.get("dimensions")
    if isinstance(dims, dict):
        for dim_name, dim in dims.items():
            checks = dim.get("checks") if isinstance(dim, dict) else None
            if not isinstance(checks, list):
                continue
            for c in checks:
                bts = c.get("blockTimestamp") if isinstance(c, dict) else None
                if not isinstance(bts, str):
                    continue
                t = parse_time_ms(bts)
                if t is None:
                    continue
                if now - t > limit_ms:
                    return _failed(f'Dimension "{dim_name}" on-chain data is {round((now - t) / 1000)}s old ({limit_text})')
    return {"passed": True}


def _check_trust_expiry(expires_at: str, skew_ms: int) -> Check:
    ts = parse_time_ms(expires_at)
    if ts is None:
        return _failed("Invalid expiresAt timestamp")
    if now_ms() > ts + skew_ms:
        return _failed("Trust profile has expired")
    return {"passed": True}


def verify_trust_profile(response: Any, **options: Any) -> Dict[str, Any]:
    """Verify an InsumerAPI trust profile from ``POST /v1/trust``.

    Accepts the full response envelope or a bare ``{trust, sig, kid}`` entry
    from ``POST /v1/trust/batch``. Reports four independent verdicts under
    ``checks``: ``signature``, ``freshness``, ``expiry`` and ``pq``. On success
    ``trust`` is the verified profile exactly as parsed from the wire; render
    that, gated on ``valid``, never your own copy of the response.

    Pass the object as parsed. Do not rebuild the ``trust`` object: the v1
    scheme signs insertion-order JSON, so changing key order changes the bytes.
    """
    opts = _options(options)
    try:
        parsed = _parse_trust_response(response)
    except Exception as e:  # noqa: BLE001
        return {
            "valid": False,
            "checks": {
                "signature": _failed(str(e)),
                "freshness": _failed("Skipped (parse failed)"),
                "expiry": _failed("Skipped (parse failed)"),
                "pq": _failed_pq("Skipped (parse failed)"),
            },
        }
    trust, sig, kid, pq_sig, pq_kid = parsed["trust"], parsed["sig"], parsed["kid"], parsed["pqSig"], parsed["pqKid"]
    key_jwk: Optional[Dict[str, str]] = None
    key_problem: Optional[str] = None
    if opts.get("jwks") is not None or opts.get("jwks_url"):
        key_jwk, key_problem = _keys.select_jwks_key(opts, kid)
    skew_ms = _clock_skew_ms(opts)
    profiled_at = str(trust.get("profiledAt") or "")
    signature = _guarded(lambda: _failed(key_problem) if key_problem else _check_trust_signature(trust, sig, key_jwk, kid), _failed)
    freshness = _guarded(lambda: _check_trust_freshness(trust, opts.get("max_age"), skew_ms), _failed)
    expiry = _guarded(lambda: _check_trust_expiry(str(trust.get("expiresAt")), skew_ms), _failed)
    pq = _guarded(
        lambda: _unknown_classical_kid_pq(kid, pq_sig, pq_kid, opts, profiled_at)
        or _check_pq_signature(PQ_TRUST_DOMAIN, lambda: classical_trust_preimage(trust, kid), pq_sig, pq_kid, opts, trust.get("profiledAt")),
        _failed_pq,
    )
    return {
        "valid": all(c["passed"] for c in (signature, freshness, expiry, pq)),
        "trust": trust,
        "checks": {"signature": signature, "freshness": freshness, "expiry": expiry, "pq": pq},
    }
