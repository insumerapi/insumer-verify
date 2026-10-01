"""insumer-verify: verifier for InsumerAPI attestations and wallet trust profiles.

    from insumer_verify import verify_attestation, verify_trust_profile

    result = verify_attestation(response_json, jwks_url="https://insumermodel.com/.well-known/jwks.json")
    if result["valid"] and response_json["data"]["attestation"]["pass"]:
        ...

Five independent verdicts on an attestation (signature, condition hashes,
freshness, expiry, post-quantum companion), four on a trust profile. The
Python and JavaScript packages implement the same specification and pass the
same published test vectors.
"""

from ._jsjson import MAX_CANONICAL_DEPTH, CanonicalDepthError, canonicalize
from ._keys import DEFAULT_JWKS_URL, PUBLIC_KEY_JWK
from .verify import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    EXPIRY_BINDING_GRACE_MS,
    classical_attest_preimage,
    classical_trust_preimage,
    condition_hash,
    verify_attestation,
    verify_trust_profile,
)

__version__ = "1.9.2.1"

__all__ = [
    "verify_attestation",
    "verify_trust_profile",
    "classical_attest_preimage",
    "classical_trust_preimage",
    "condition_hash",
    "canonicalize",
    "CanonicalDepthError",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "EXPIRY_BINDING_GRACE_MS",
    "MAX_CANONICAL_DEPTH",
    "DEFAULT_JWKS_URL",
    "PUBLIC_KEY_JWK",
    "__version__",
]
