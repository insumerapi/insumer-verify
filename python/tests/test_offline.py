"""Offline verification against a saved key set, and the key-selection rules.

Ports the JavaScript package's test-offline suite: real issuer responses are
verified with the network disabled, a supplied set takes precedence over a URL,
missing keys are never fetched, and a key the set does not hold fails the
signature verdict alone.
"""

from insumer_verify import verify_attestation, verify_trust_profile


def test_saved_set_verifies_real_responses_with_network_disabled(vectors, saved_jwks, no_network):
    for name, is_trust in (
        ("12-pq-companion-v2", False),
        ("13-pq-companion-v1", False),
        ("14-pq-companion-tampered", False),
        ("18-trust-profile-not-evaluated", True),
    ):
        v = vectors[name]
        out = (verify_trust_profile if is_trust else verify_attestation)(v["response"], jwks=saved_jwks)
        for k, want in v["expected"]["checks"].items():
            assert out["checks"][k]["passed"] is want, (name, k, out["checks"][k])
        assert out["checks"]["pq"]["status"] == v["expected"]["pq"]["status"], (name, out["checks"]["pq"])
    assert no_network["n"] == 0


def test_supplied_set_takes_precedence_over_jwks_url(vectors, saved_jwks, no_network):
    v = vectors["12-pq-companion-v2"]
    out = verify_attestation(v["response"], jwks_url="https://example.invalid/jwks.json", jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is True, out["checks"]["signature"]
    assert out["checks"]["pq"]["status"] == "verified", out["checks"]["pq"]
    assert no_network["n"] == 0


def test_supplied_set_is_honoured_exactly(vectors, saved_jwks, no_network):
    v = vectors["12-pq-companion-v2"]
    no_pq = {"keys": [k for k in saved_jwks["keys"] if k["kty"] != "AKP"]}
    out1 = verify_attestation(v["response"], jwks=no_pq)
    assert out1["checks"]["signature"]["passed"] is True
    assert out1["checks"]["pq"]["status"] == "unverifiable"
    no_ec = {"keys": [k for k in saved_jwks["keys"] if k["kty"] != "EC"]}
    out2 = verify_attestation(v["response"], jwks=no_ec)
    assert out2["checks"]["signature"]["passed"] is False
    out3 = verify_attestation(v["response"], jwks={})
    assert out3["checks"]["signature"]["passed"] is False
    assert no_network["n"] == 0


def test_key_not_in_set_fails_signature_alone(vectors, saved_jwks, no_network):
    v = vectors["12-pq-companion-v2"]
    no_v2 = {"keys": [k for k in saved_jwks["keys"] if k.get("kid") != "insumer-attest-v2"]}
    out = verify_attestation(v["response"], jwks=no_v2, mode="evidence")
    assert out["checks"]["signature"]["passed"] is False
    assert "no key matching kid" in out["checks"]["signature"]["reason"]
    assert out["checks"]["conditionHashes"]["passed"] is True
    assert out["checks"]["pq"]["status"] == "verified"
    assert out["valid"] is False
    assert no_network["n"] == 0


def test_built_in_key_is_never_used_when_a_set_is_supplied(vectors, saved_jwks, no_network):
    # A set that lacks the kid must not fall back to the embedded key, even
    # though the embedded key would verify this real response.
    v = vectors["01-token-balance-met"]
    assert verify_attestation(v["response"])["checks"]["signature"]["passed"] is True
    out = verify_attestation(v["response"], jwks={"keys": []})
    assert out["checks"]["signature"]["passed"] is False


def test_evidence_mode_never_refuses_for_a_missing_companion(vectors, saved_jwks, no_network):
    v = vectors["16-pq-absent-under-cutoff"]
    access = verify_attestation(v["response"], jwks=saved_jwks, pq_required_from="2026-09-01T00:00:00Z")
    evidence = verify_attestation(v["response"], jwks=saved_jwks, pq_required_from="2026-09-01T00:00:00Z", mode="evidence")
    assert access["checks"]["pq"] == {**access["checks"]["pq"], "status": "absent", "passed": False}
    assert evidence["checks"]["pq"]["status"] == "absent"
    assert evidence["checks"]["pq"]["passed"] is True


def test_existed_at_issuance_is_reporting_only(vectors, saved_jwks, no_network):
    v = vectors["13-pq-companion-v1"]
    out = verify_attestation(v["response"], jwks=saved_jwks, pq_activated_at="2026-09-01T23:30:53Z")
    assert out["checks"]["pq"]["status"] == "verified"
    assert out["checks"]["pq"]["existedAtIssuance"] is True
    early = verify_attestation(vectors["01-token-balance-met"]["response"], jwks=saved_jwks, pq_activated_at="2026-09-01T23:30:53Z")
    assert early["checks"]["pq"]["status"] == "absent"
    assert early["checks"]["pq"]["existedAtIssuance"] is False
    assert early["checks"]["pq"]["passed"] is True


def test_inner_data_object_is_rejected_with_the_documented_error(vectors):
    import pytest

    with pytest.raises(ValueError, match="missing data object"):
        verify_attestation(vectors["01-token-balance-met"]["response"]["data"])


def test_unknown_option_is_a_type_error(vectors):
    import pytest

    with pytest.raises(TypeError, match="unknown option"):
        verify_attestation(vectors["01-token-balance-met"]["response"], jwksUrl="https://example.invalid")


def test_bare_jwt_string_path(vectors, saved_jwks, no_network):
    # Vector 26 is a whole format:"jwt" response; its data.jwt verified alone
    # with pq_jwt supplied reports the same verdicts on the token.
    data = vectors["26-jwt-format-whole-response"]["response"]["data"]
    out = verify_attestation(data["jwt"], jwks=saved_jwks, pq_jwt=data["pqJwt"])
    assert out["checks"]["signature"]["passed"] is True
    assert out["checks"]["conditionHashes"]["passed"] is True
    assert out["checks"]["pq"]["status"] == "verified"
    assert out["checks"]["expiry"]["passed"] is False  # issued 2026-09-20
    alone = verify_attestation(data["jwt"], jwks=saved_jwks)
    assert alone["checks"]["pq"]["status"] == "absent"
    assert "pass pq_jwt" in alone["checks"]["pq"]["reason"]


def test_jwt_envelope_without_attestation_routes_to_jwt_path(vectors, saved_jwks, no_network):
    data = vectors["26-jwt-format-whole-response"]["response"]["data"]
    envelope = {"ok": True, "data": {"jwt": data["jwt"], "pqJwt": data["pqJwt"]}}
    out = verify_attestation(envelope, jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is True
    assert out["checks"]["pq"]["status"] == "verified"
    assert "jwt" not in out["checks"]


def test_trust_batch_entry_shape(vectors, saved_jwks, no_network):
    data = vectors["18-trust-profile-not-evaluated"]["response"]["data"]
    entry = {k: data[k] for k in ("trust", "sig", "kid", "pqSig", "pqKid") if k in data}
    out = verify_trust_profile(entry, jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is True
    assert out["checks"]["pq"]["status"] == "verified"
    assert out["trust"] is data["trust"]


def test_non_trust_object_is_refused_by_the_structural_gate(vectors, saved_jwks, no_network):
    data = vectors["01-token-balance-met"]["response"]["data"]
    out = verify_trust_profile({"data": {"trust": data["attestation"], "sig": data["sig"], "kid": data.get("kid")}}, jwks=saved_jwks)
    assert out["valid"] is False
    assert "not a trust profile" in out["checks"]["signature"]["reason"]
    assert "trust" not in out
