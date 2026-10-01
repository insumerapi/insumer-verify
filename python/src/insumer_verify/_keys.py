"""Key material: the built-in ECDSA key, JWKS resolution by ``kid``, and the signature primitives.

The JWKS holds keys of two types. The first three entries are one ECDSA P-256
key under three ``kid`` values; the last two are RFC 9964 ``AKP`` entries for
the ML-DSA-65 post-quantum companion key. Keys are selected by ``kid`` and
never by position.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

#: InsumerAPI's ECDSA P-256 public key in JWK form. The same key is published
#: at https://insumermodel.com/.well-known/jwks.json under three kids.
PUBLIC_KEY_JWK: Dict[str, str] = {
    "kty": "EC",
    "crv": "P-256",
    "x": "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
    "y": "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
}

DEFAULT_JWKS_URL = "https://insumermodel.com/.well-known/jwks.json"
JWKS_FETCH_TIMEOUT_SECONDS = 15

# Which classical kids may sign which artifact. Attestations and trust profiles
# share the v1 kid (one frozen scheme) but have distinct v2 kids; a trust kid on
# an attestation, or the reverse, is a mislabelled artifact and fails Check 1
# rather than being re-interpreted.
ATTEST_KIDS = frozenset({"insumer-attest-v1", "insumer-attest-v2"})
TRUST_KIDS = frozenset({"insumer-attest-v1", "insumer-trust-v2"})
KNOWN_PQ_KIDS = frozenset({"insumer-attest-pq1", "insumer-trust-pq1"})
KNOWN_CLASSICAL_KIDS = ATTEST_KIDS | TRUST_KIDS


# ── Encoding helpers ─────────────────────────────────────────────────


def b64_decode(text: str) -> bytes:
    """Standard base64 (what ``atob`` reads), padding tolerated."""
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    cleaned = "".join(text.split())
    pad = (-len(cleaned)) % 4
    if pad == 3:
        raise ValueError("invalid base64 length")
    return base64.b64decode(cleaned + "=" * pad, validate=True)


def b64url_decode(text: str) -> bytes:
    """base64url with or without padding."""
    if not isinstance(text, str):
        raise ValueError("expected a base64url string")
    cleaned = text.replace("-", "+").replace("_", "/")
    return b64_decode(cleaned)


def b64url_decode_text(text: str) -> str:
    return b64url_decode(text).decode("utf-8")


# ── JWKS loading and selection ───────────────────────────────────────


def load_jwks(options: Dict[str, Any], fallback_url: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
    """The key set to resolve against: a supplied object (nothing fetched) or the JWKS at a URL.

    Returns the set and a label naming its source for error messages.
    """
    supplied = options.get("jwks")
    if supplied is not None:
        if not isinstance(supplied, dict) or not isinstance(supplied.get("keys"), list):
            raise ValueError("Supplied jwks has no keys array")
        return supplied, "supplied JWKS"
    url = options.get("jwks_url") or fallback_url or DEFAULT_JWKS_URL
    fetch: Callable[[str], Dict[str, Any]] = options.get("_fetch_json") or _fetch_json
    return fetch(url), f"JWKS at {url}"


def _fetch_json(url: str) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "insumer-verify-python"})
    try:
        with urllib.request.urlopen(request, timeout=JWKS_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310 (https URL supplied by the caller)
            status = getattr(response, "status", 200)
            if status != 200:
                raise ValueError(f"JWKS fetch failed: {status} {getattr(response, 'reason', '')}".rstrip())
            body = response.read()
    except urllib.error.HTTPError as e:
        raise ValueError(f"JWKS fetch failed: {e.code} {e.reason}") from None
    except urllib.error.URLError as e:
        raise ValueError(f"JWKS fetch failed: {e.reason}") from None
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"JWKS fetch failed: response is not JSON ({e})") from None
    if not isinstance(parsed, dict):
        raise ValueError("JWKS fetch failed: response is not a JSON object")
    return parsed


def fetch_jwks_key(options: Dict[str, Any], kid: Optional[str]) -> Dict[str, str]:
    """The P-256 JWK the response's kid names, or an error naming why none could be selected."""
    jwks, label = load_jwks(options)
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("JWKS response contains no keys")
    # A kid that resolves to nothing is a failure, not a reason to fall back: the
    # first key in the document is not the key the signature claims. A response
    # with no kid cannot select a key at all (spec Section 3.4 makes kid
    # mandatory): the set holds keys of two types, and position is not a contract.
    if not kid:
        raise ValueError("Response carries no kid; the signing key cannot be selected")
    key = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
    if key is None:
        raise ValueError(f'{label} has no key matching kid "{kid}"')
    if key.get("kty") != "EC" or key.get("crv") != "P-256":
        raise ValueError(f'JWKS key "{kid}" is not a P-256 EC key; a classical signature cannot be verified with it')
    return {"kty": "EC", "crv": "P-256", "x": str(key.get("x")), "y": str(key.get("y"))}


def select_jwks_key(options: Dict[str, Any], kid: Optional[str]) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """Key selection as a verdict, not an escape.

    When a key set is in play and the response's kid selects no usable key in
    it, the failure belongs to the signature verdict alone: the other checks
    need no key and are still performed. Returns ``(key, None)`` or
    ``(None, reason)``. Nothing is ever substituted.
    """
    try:
        return fetch_jwks_key(options, kid), None
    except Exception as e:  # noqa: BLE001 (every failure is a reason, never an escape)
        return None, f"JWKS fetch error: {e}"


def fetch_pq_key(options: Dict[str, Any], pq_kid: str) -> bytes:
    """The raw ML-DSA-65 public key the JWKS lists under ``pq_kid`` (RFC 9964 ``AKP``)."""
    jwks, label = load_jwks(options)
    keys = jwks.get("keys") or []
    key = next((k for k in keys if isinstance(k, dict) and k.get("kid") == pq_kid), None)
    if key is None:
        raise ValueError(f'{label} has no key matching pqKid "{pq_kid}"')
    if key.get("kty") != "AKP" or key.get("alg") != "ML-DSA-65" or not isinstance(key.get("pub"), str):
        raise ValueError(f'JWKS key "{pq_kid}" is not an RFC 9964 ML-DSA-65 key')
    return b64url_decode(key["pub"])


# ── ECDSA P-256 ──────────────────────────────────────────────────────


def ec_public_key(jwk: Dict[str, str]) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _der_from_signature(sig: bytes, accept_der: bool) -> bytes:
    if len(sig) == 64:
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        return encode_dss_signature(r, s)
    if accept_der and sig[:1] == b"\x30":
        r, s = decode_dss_signature(sig)  # raises on malformed DER
        return encode_dss_signature(r, s)
    raise ValueError(f"signature is {len(sig)} bytes; expected 64 (P1363 r || s)")


def ecdsa_verify(jwk: Dict[str, str], signature: bytes, message: bytes, accept_der: bool = False) -> bool:
    """ECDSA P-256 / SHA-256 over ``message``.

    ``signature`` is raw P1363 ``r || s`` (what the API emits); on the JWT path
    a DER-encoded signature is accepted too. Returns ``False`` for a signature
    that does not verify and raises for a key or encoding that cannot be used.
    """
    key = ec_public_key(jwk)
    der = _der_from_signature(signature, accept_der)
    try:
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── ML-DSA-65 (post-quantum companion) ───────────────────────────────

_ml_dsa_loaded = False
_ml_dsa_verify: Optional[Callable[[bytes, bytes, bytes], bool]] = None


def load_ml_dsa() -> Optional[Callable[[bytes, bytes, bytes], bool]]:
    """``verify(signature, message, public_key) -> bool`` for ML-DSA-65, or ``None``.

    ML-DSA is not in the standard library, so verification uses ``dilithium-py``
    when it is installed (``pip install insumer-verify[pq]``). Without it the
    companion is reported ``unverifiable``: never a silent pass, never a silent
    failure. FIPS 204 pure mode with an empty context, as the issuer signs.
    """
    global _ml_dsa_loaded, _ml_dsa_verify
    if _ml_dsa_loaded:
        return _ml_dsa_verify
    _ml_dsa_loaded = True
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 (any import problem means "not available")
        _ml_dsa_verify = None
        return None

    def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
        return bool(ML_DSA_65.verify(public_key, message, signature))

    _ml_dsa_verify = verify
    return verify


PQ_UNAVAILABLE_REASON = "ML-DSA verifier unavailable in this runtime (install dilithium-py, or insumer-verify[pq])"
