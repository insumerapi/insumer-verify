"""Hostile nesting is refused as a failed check, never a crash and never a pass.

Ports the JavaScript package's test-depth suite. Canonicalization runs beside
signature verification, so anyone holding an artifact can reach the recursive
walk; the bound turns a deliberately deep artifact into a verdict that names
the refusal.
"""

import re

from insumer_verify import MAX_CANONICAL_DEPTH, verify_attestation, verify_trust_profile

REFUSED = re.compile(r"too deeply nested|nests deeper", re.I)


def nest_obj(n):
    o = {"leaf": 1}
    for _ in range(n):
        o = {"a": o}
    return o


def nest_arr(n):
    a = [1]
    for _ in range(n):
        a = [a]
    return a


def artifact(evaluated_condition, kid):
    return {
        "ok": True,
        "data": {
            "attestation": {
                "id": "depth-probe",
                "pass": True,
                "results": [{"condition": 0, "met": True, "conditionHash": "0x00", "evaluatedCondition": evaluated_condition}],
                "attestedAt": "2026-09-20T00:00:00.000Z",
                "expiresAt": "2026-09-20T00:30:00.000Z",
            },
            "sig": "AAAA",
            "kid": kid,
        },
    }


def test_bound_is_128():
    assert MAX_CANONICAL_DEPTH == 128


def test_deep_object_is_refused_not_thrown_on_both_schemes():
    for kid in ("insumer-attest-v1", "insumer-attest-v2"):
        r = verify_attestation(artifact(nest_obj(50000), kid))
        assert r["valid"] is False
        assert REFUSED.search(r["checks"]["signature"]["reason"]), (kid, r["checks"]["signature"])
        assert REFUSED.search(r["checks"]["conditionHashes"]["reason"]), (kid, r["checks"]["conditionHashes"])


def test_deep_array_is_refused_too():
    # A recursive call that took a list index for the depth would miss this.
    r = verify_attestation(artifact(nest_arr(50000), "insumer-attest-v2"))
    assert REFUSED.search(r["checks"]["signature"]["reason"])
    assert REFUSED.search(r["checks"]["conditionHashes"]["reason"])


def test_normal_depth_is_untouched():
    for depth in (9, 120):
        r = verify_attestation(artifact(nest_obj(depth), "insumer-attest-v2"))
        assert not REFUSED.search(r["checks"]["signature"].get("reason", ""))
        assert not REFUSED.search(r["checks"]["conditionHashes"].get("reason", ""))


def test_companion_absent_stays_absent_on_a_deep_artifact(saved_jwks, no_network):
    r = verify_attestation(artifact(nest_obj(200), "insumer-attest-v2"), jwks=saved_jwks)
    assert r["checks"]["pq"]["status"] == "absent"
    assert r["checks"]["pq"]["passed"] is True
    with_pq = artifact(nest_obj(200), "insumer-attest-v2")
    with_pq["data"]["pqSig"] = "AAAA"
    with_pq["data"]["pqKid"] = "insumer-attest-pq1"
    r2 = verify_attestation(with_pq, jwks=saved_jwks)
    assert r2["checks"]["pq"]["status"] == "unverifiable"
    assert REFUSED.search(r2["checks"]["pq"]["reason"]), r2["checks"]["pq"]


def test_deep_trust_profile_returns_a_verdict(saved_jwks, no_network):
    trust = {
        "id": "t",
        "wallet": "0x" + "ab" * 20,
        "conditionSetVersion": "v2",
        "dimensions": {"deep": nest_obj(200)},
        "summary": {"s": 1},
        "profiledAt": "2026-09-20T00:00:00.000Z",
        "expiresAt": "2026-09-20T00:30:00.000Z",
    }
    r = verify_trust_profile({"data": {"trust": trust, "sig": "AAAA", "kid": "insumer-trust-v2"}}, jwks=saved_jwks)
    assert r["valid"] is False
    assert REFUSED.search(r["checks"]["signature"]["reason"]), r["checks"]["signature"]
    assert r["checks"]["pq"]["status"] == "absent"
    r2 = verify_trust_profile({"data": {"trust": trust, "sig": "AAAA", "kid": "insumer-trust-v2", "pqSig": "AAAA", "pqKid": "insumer-trust-pq1"}}, jwks=saved_jwks)
    assert r2["checks"]["pq"]["status"] == "unverifiable"
    assert REFUSED.search(r2["checks"]["pq"]["reason"])
