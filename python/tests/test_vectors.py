"""Every published conformance vector, offline.

The vectors that pin ``jwksUrl`` are run against a saved copy of the same key
set with the network disabled, which proves both that the verdicts match the
published expectations and that a record-keeper with a saved JWKS needs no
network. Set ``INSUMER_VERIFY_NETWORK=1`` to run them against the live URL
instead.
"""

import json
import os

import pytest

from insumer_verify import verify_attestation, verify_trust_profile

from .conftest import is_trust_vector, snake_options

LIVE = os.environ.get("INSUMER_VERIFY_NETWORK") == "1"

VECTOR_IDS = [
    "01-token-balance-met",
    "02-token-balance-not-met",
    "03-token-balance-dai",
    "04-token-balance-weth",
    "05-multi-condition-mixed",
    "06-second-chain-base",
    "07-non-evm-anchor-bitcoin",
    "08-tampered-condition",
    "09-tampered-signature",
    "10-tampered-condition-hash",
    "11-unresolvable-kid",
    "12-pq-companion-v2",
    "13-pq-companion-v1",
    "14-pq-companion-tampered",
    "15-pq-kid-unresolvable",
    "16-pq-absent-under-cutoff",
    "17-pq-jwt-companion",
    "18-trust-profile-not-evaluated",
    "19-missing-kid",
    "20-attest-under-trust-kid",
    "21-trust-under-attest-kid",
    "22-pq-kid-other-artifact",
    "23-unknown-kid-no-jwks",
    "24-pq-jwt-subject-differs",
    "25-pq-jwt-results-differ",
    "26-jwt-format-whole-response",
    "27-jwt-format-token-edited",
]


def test_fixture_carries_every_vector(vectors):
    assert sorted(vectors) == VECTOR_IDS


def run_vector(vector, saved_jwks):
    options = snake_options(vector.get("options"))
    if "jwks_url" in options and not LIVE:
        del options["jwks_url"]
        options["jwks"] = saved_jwks
    if is_trust_vector(vector):
        return verify_trust_profile(vector["response"], **options)
    return verify_attestation(vector["response"], **options)


@pytest.mark.parametrize("vector_id", VECTOR_IDS)
def test_vector_matches_published_expectation(vector_id, vectors, saved_jwks, monkeypatch):
    vector = vectors[vector_id]
    if not LIVE:
        import insumer_verify._keys as keys

        def fail(url):
            raise AssertionError(f"unexpected network fetch of {url}")

        monkeypatch.setattr(keys, "_fetch_json", fail)
    out = run_vector(vector, saved_jwks)
    expected = vector["expected"]
    for name, want in expected["checks"].items():
        got = out["checks"].get(name)
        assert got is not None, f"{vector_id}: check {name} missing"
        assert got["passed"] is want, f"{vector_id}: checks.{name} expected {want}, got {got}"
    if "pq" in expected and "status" in expected["pq"]:
        assert out["checks"]["pq"]["status"] == expected["pq"]["status"], out["checks"]["pq"]
    assert out["valid"] is all(expected["checks"].values())
    # The vector's own statements about its content.
    if "attestation" in expected:
        att = vector["response"]["data"]["attestation"]
        assert att["pass"] is expected["attestation"]["pass"]
        for i, r in enumerate(expected["attestation"]["results"]):
            assert att["results"][i]["met"] is r["met"]
    if "trust" in expected:
        assert out["trust"]["summary"] == {**out["trust"]["summary"], **expected["trust"]["summary"]}


def test_every_check_is_reported_on_a_failing_artifact(vectors, saved_jwks, no_network):
    # Vector 09: the signature fails, the hashes still reproduce, and the verifier
    # says so for each check separately rather than collapsing on the first failure.
    out = verify_attestation(vectors["09-tampered-signature"]["response"], jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is False
    assert out["checks"]["conditionHashes"]["passed"] is True
    assert out["checks"]["expiry"]["passed"] is False  # long expired
    assert "reason" in out["checks"]["signature"]


def test_recompute_blocks_reproduce(vectors):
    # Each vector states the canonical evaluatedCondition and the hash a verifier
    # should compute. Recompute both and compare.
    from insumer_verify import condition_hash
    from insumer_verify._jsjson import canonicalize, v1_condition_canonical

    for vector_id, vector in vectors.items():
        if is_trust_vector(vector):
            continue
        data = vector["response"]["data"]
        if "attestation" in data:
            kid = data.get("kid")
            results = data["attestation"]["results"]
        else:  # the JWT-only envelope: the results and kid live in the token
            import base64

            header, payload = (json.loads(base64.urlsafe_b64decode(seg + "==").decode()) for seg in data["jwt"].split(".")[:2])
            kid = header.get("kid")
            results = payload["results"]
        for r, rec in zip(results, vector["recompute"]):
            ec = r["evaluatedCondition"]
            canonical = canonicalize(ec) if kid == "insumer-attest-v2" else v1_condition_canonical(ec)
            assert canonical == rec["canonicalEvaluatedCondition"], vector_id
            computed = condition_hash(ec, kid)
            assert (computed == r["conditionHash"]) is rec["reproduces"], vector_id
