"""Inputs the published vectors do not exercise, with the verdict the JavaScript reference gives.

Each expectation below was produced by running the same input through the
reference verifier (compiled from ``src/index.ts``) during an adversarial
parity review. Where this package deliberately differs, the test says so.
"""

import base64
import copy
import json

import pytest

from insumer_verify import verify_attestation, verify_trust_profile
from insumer_verify._keys import der_to_p1363

from .conftest import load


def b64u(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def b64u_raw(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


@pytest.fixture
def v1(vectors):
    return copy.deepcopy(vectors["01-token-balance-met"]["response"])


# ── base64 exactly as atob ───────────────────────────────────────────


def test_signature_with_one_padding_char_stripped_is_refused(v1, saved_jwks, no_network):
    v1["data"]["sig"] = v1["data"]["sig"][:-1]
    out = verify_attestation(v1, jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is False
    assert "Invalid character" in out["checks"]["signature"]["reason"]


def test_ascii_whitespace_inside_signature_is_ignored_but_unicode_whitespace_is_not(v1, saved_jwks, no_network):
    sig = v1["data"]["sig"]
    spaced = copy.deepcopy(v1)
    spaced["data"]["sig"] = sig[:10] + " \n" + sig[10:]
    assert verify_attestation(spaced, jwks=saved_jwks)["checks"]["signature"]["passed"] is True
    nbsp = copy.deepcopy(v1)
    nbsp["data"]["sig"] = sig[:10] + " " + sig[10:]
    assert verify_attestation(nbsp, jwks=saved_jwks)["checks"]["signature"]["passed"] is False


def test_der_signature_on_the_raw_path_is_a_mismatch_not_an_error(v1, saved_jwks, no_network):
    raw = base64.b64decode(v1["data"]["sig"])
    der = b"\x30\x44\x02\x20" + raw[:32] + b"\x02\x20" + raw[32:]
    v1["data"]["sig"] = base64.b64encode(der).decode()
    out = verify_attestation(v1, jwks=saved_jwks)
    assert out["checks"]["signature"] == {"passed": False, "reason": "Signature does not match payload"}


def test_non_minimal_der_in_a_jwt_is_accepted_like_the_reference(vectors, saved_jwks, no_network):
    jwt = vectors["17-pq-jwt-companion"]["response"]["data"]["jwt"]
    h, p, s = jwt.split(".")
    raw = base64.urlsafe_b64decode(s + "==")
    r, sv = raw[:32], raw[32:]
    der = b"\x30" + bytes([4 + 1 + len(r) + len(sv)]) + b"\x02" + bytes([len(r) + 1]) + b"\x00" + r + b"\x02" + bytes([len(sv)]) + sv
    assert der_to_p1363(der) == raw
    token = f"{h}.{p}." + base64.urlsafe_b64encode(der).decode().rstrip("=")
    out = verify_attestation(token, jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is True


# ── key sets ─────────────────────────────────────────────────────────


def test_null_entry_before_the_match_fails_the_signature(v1, saved_jwks, no_network):
    out = verify_attestation(v1, jwks={"keys": [None] + saved_jwks["keys"]})
    assert out["checks"]["signature"]["passed"] is False
    assert "not a key object" in out["checks"]["signature"]["reason"]
    after = verify_attestation(v1, jwks={"keys": saved_jwks["keys"] + [None]})
    assert after["checks"]["signature"]["passed"] is True


def test_non_dict_jwks_is_a_type_error_not_a_silent_fallback(v1):
    # The reference treats a falsy jwks as unset and uses its built-in key. This
    # package refuses the call instead: neither verifier is silently weaker.
    for bad in ("", 0, False, [], "https://example.invalid/jwks.json"):
        with pytest.raises(TypeError, match="jwks must be a dict"):
            verify_attestation(v1, jwks=bad)


# ── caller policy ────────────────────────────────────────────────────


def test_falsy_cutoffs_are_unset(v1, saved_jwks, no_network):
    out = verify_attestation(v1, jwks=saved_jwks, pq_required_from=0, pq_activated_at="")
    assert out["checks"]["pq"]["status"] == "absent"
    assert out["checks"]["pq"]["passed"] is True
    assert "existedAtIssuance" not in out["checks"]["pq"]


def test_unreadable_cutoff_is_an_error_not_a_weaker_policy(v1):
    # The reference reads "Jan 1 2020"; this package reads ISO 8601 only, and a
    # cutoff it cannot read must never degrade to "companion not required".
    with pytest.raises(ValueError, match="pq_required_from"):
        verify_attestation(v1, pq_required_from="Jan 1 2020")
    with pytest.raises(ValueError, match="pq_activated_at"):
        verify_attestation(v1, pq_activated_at="Sep 1 2026")


def test_numeric_options_must_be_numbers(v1):
    with pytest.raises(TypeError, match="max_age"):
        verify_attestation(v1, max_age="1000000000")
    with pytest.raises(TypeError, match="clock_skew"):
        verify_attestation(v1, clock_skew=True)


def test_infinite_clock_skew_falls_back_to_the_default(v1, saved_jwks, no_network):
    out = verify_attestation(v1, jwks=saved_jwks, clock_skew=float("inf"))
    assert out["checks"]["expiry"] == {"passed": False, "reason": "Attestation has expired"}


# ── timestamps as Date reads them ────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "2026-08-28T22:54:60.000Z",
        "2026-08-28T25:00:00Z",
        "2026-08-32T22:54:00Z",
        "2026-08-28T23:60:00Z",
        "2026-08-28T24:00:01Z",
        "2026-08-28T22:54:00+24:00",
        "2026-08-28T22:54:00+05:60",
        " 2026-08-28T22:55:11.944Z",
        "2026-08-28T22:55:11.944Z\n",
    ],
)
def test_out_of_range_or_padded_expires_at_is_invalid(v1, saved_jwks, no_network, bad):
    v1["data"]["attestation"]["expiresAt"] = bad
    out = verify_attestation(v1, jwks=saved_jwks)
    assert out["checks"]["expiry"] == {"passed": False, "reason": "Invalid expiresAt timestamp"}, bad


def test_day_past_month_end_rolls_over_like_v8():
    from insumer_verify._time import parse_iso_ms

    assert parse_iso_ms("2024-02-30T00:00:00Z") == parse_iso_ms("2024-03-01T00:00:00Z")
    assert parse_iso_ms("2023-02-29T00:00:00Z") == parse_iso_ms("2023-03-01T00:00:00Z")
    assert parse_iso_ms("2024-13-01T00:00:00Z") is None
    assert parse_iso_ms("2026-08-28T24:00:00Z") == parse_iso_ms("2026-08-29T00:00:00Z")
    assert parse_iso_ms("2026-08-28T22:54:11.9440000000Z") == parse_iso_ms("2026-08-28T22:54:11.944Z")


def test_attested_at_with_many_fraction_digits_still_binds_expires_at(v1, saved_jwks, no_network):
    v1["data"]["attestation"]["attestedAt"] = "2026-08-28T22:25:11.9440000000Z"
    v1["data"]["attestation"]["expiresAt"] = "2099-01-01T00:00:00.000Z"
    out = verify_attestation(v1, jwks=saved_jwks)
    assert "exceeds the signed issuance window" in out["checks"]["expiry"]["reason"]


def test_boolean_block_timestamp_is_the_epoch_plus_one_ms(v1, saved_jwks, no_network):
    v1["data"]["attestation"]["results"][0]["blockTimestamp"] = True
    out = verify_attestation(v1, jwks=saved_jwks, max_age=10**9)
    assert out["checks"]["freshness"]["passed"] is False
    assert "old" in out["checks"]["freshness"]["reason"]


# ── hostile shapes inside the signed payload ─────────────────────────


def test_null_result_is_a_verification_error_on_every_check_that_reads_it(v1, saved_jwks, no_network):
    v1["data"]["attestation"]["results"] = [None]
    out = verify_attestation(v1, jwks=saved_jwks, max_age=10**9)
    for name in ("conditionHashes", "freshness", "expiry"):
        assert out["checks"][name]["passed"] is False
        assert out["checks"][name]["reason"].startswith("Verification error"), (name, out["checks"][name])
    assert "failures" not in out["checks"]["conditionHashes"]


def test_string_results_in_a_bare_jwt_fail_the_hashes_per_character(saved_jwks, no_network):
    token = b64u({"alg": "ES256", "kid": "insumer-attest-v2"}) + "." + b64u({"exp": 4102444800, "results": "abc"}) + ".AAAA"
    out = verify_attestation(token, jwks=saved_jwks)
    assert out["checks"]["conditionHashes"]["failures"] == [0, 1, 2]


def test_trust_dimensions_as_an_array_are_still_scanned_for_freshness(vectors, saved_jwks, no_network):
    v18 = copy.deepcopy(vectors["18-trust-profile-not-evaluated"]["response"])
    v18["data"]["trust"]["dimensions"] = list(v18["data"]["trust"]["dimensions"].values())
    v18["data"]["trust"]["profiledAt"] = "2099-01-01T00:00:00.000Z"  # profile-level age is negative, so only the per-check anchors can fail
    out = verify_trust_profile(v18, jwks=saved_jwks, max_age=1)
    assert out["checks"]["freshness"]["passed"] is False
    assert "on-chain data is" in out["checks"]["freshness"]["reason"]


# ── bare JWT claims ──────────────────────────────────────────────────


def test_numeric_string_exp_is_coerced(saved_jwks, no_network):
    token = b64u({"alg": "ES256", "kid": "insumer-attest-v2"}) + "." + b64u({"exp": "4102444800", "results": []}) + ".AAAA"
    out = verify_attestation(token, jwks=saved_jwks)
    assert out["checks"]["expiry"]["passed"] is True


def test_exp_past_year_9999_is_still_a_time_value(saved_jwks, no_network):
    token = b64u({"alg": "ES256", "kid": "insumer-attest-v2"}) + "." + b64u({"exp": 253402300800, "results": []}) + ".AAAA"
    out = verify_attestation(token, jwks=saved_jwks)
    assert out["checks"]["expiry"]["passed"] is True


def test_exp_beyond_the_date_range_is_an_error_in_the_call(saved_jwks, no_network):
    token = b64u({"alg": "ES256", "kid": "insumer-attest-v2"}) + "." + b64u({"exp": 10**16, "results": []}) + ".AAAA"
    with pytest.raises(ValueError, match="Invalid time value"):
        verify_attestation(token, jwks=saved_jwks)


def test_infinity_literal_in_a_payload_is_a_parse_error(saved_jwks, no_network):
    token = b64u({"alg": "ES256", "kid": "insumer-attest-v2"}) + "." + b64u_raw('{"exp":Infinity,"results":[]}') + ".AAAA"
    out = verify_attestation(token, jwks=saved_jwks)
    assert out["valid"] is False
    assert out["checks"]["signature"]["reason"].startswith("JWT parse error")


def test_pqjwt_with_a_numeric_kid_is_unverifiable_not_refuted(vectors, saved_jwks, no_network):
    jwt = vectors["17-pq-jwt-companion"]["response"]["data"]["jwt"]
    pq = b64u({"alg": "ML-DSA-65", "kid": 5}) + "." + b64u({}) + ".AAAA"
    out = verify_attestation(jwt, jwks=saved_jwks, pq_jwt=pq)
    assert out["checks"]["pq"]["status"] == "unverifiable"
    assert out["checks"]["pq"]["kid"] == 5
    assert out["checks"]["pq"]["passed"] is True


def test_jwt_envelope_with_a_falsy_attestation_routes_to_the_jwt_path(vectors, saved_jwks, no_network):
    d = vectors["17-pq-jwt-companion"]["response"]["data"]
    out = verify_attestation({"data": {"jwt": d["jwt"], "pqJwt": d["pqJwt"], "attestation": False}}, jwks=saved_jwks)
    assert out["checks"]["signature"]["passed"] is True
    assert out["checks"]["pq"]["status"] == "verified"


def test_embedded_jwt_exp_binding_fails_on_an_unparsable_expires_at(vectors, saved_jwks, no_network):
    v26 = copy.deepcopy(vectors["26-jwt-format-whole-response"]["response"])
    v26["data"]["attestation"]["expiresAt"] = "garbage"
    out = verify_attestation(v26, jwks=saved_jwks)
    assert out["checks"]["jwt"]["passed"] is False
    assert 'claim "exp" differs' in out["checks"]["jwt"]["reason"]
    assert out["checks"]["jwt"]["pq"]["status"] == "verified"


def test_non_string_kid_is_carried_into_the_reason(v1, saved_jwks, no_network):
    v1["data"]["kid"] = 5
    out = verify_attestation(v1, jwks=saved_jwks)
    assert out["checks"]["signature"]["reason"] == 'JWKS fetch error: supplied JWKS has no key matching kid "5"'
    v1["data"]["kid"] = True
    out = verify_attestation(v1)
    assert out["checks"]["signature"]["reason"] == 'kid "true" does not sign attestations'


def test_list_input_to_trust_is_a_missing_profile():
    out = verify_trust_profile([])
    assert out["checks"]["signature"]["reason"].startswith("Missing trust profile")
