"""Live proof against production, on both key eras.

Skipped unless API keys are supplied in the environment:

    INSUMER_API_KEY_V2=insr_live_...   a key created on or after the v2 rollout
    INSUMER_API_KEY_V1=insr_live_...   a key on the frozen v1 scheme

Each call spends one credit (three for a trust profile). The responses are
verified with the live JWKS, and every verdict, including the post-quantum
companion, must be clean.
"""

import json
import os
import urllib.request

import pytest

from insumer_verify import verify_attestation, verify_trust_profile

API = "https://api.insumermodel.com"
JWKS = "https://insumermodel.com/.well-known/jwks.json"
WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


def post(path, key, body):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": key, "User-Agent": "insumer-verify-python-tests"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as res:
        return json.loads(res.read().decode("utf-8"))


def keys():
    out = []
    for era in ("v2", "v1"):
        k = os.environ.get(f"INSUMER_API_KEY_{era.upper()}")
        if k:
            out.append(pytest.param(k, era, id=era))
    return out


@pytest.mark.skipif(not keys(), reason="no INSUMER_API_KEY_V1/V2 in the environment")
@pytest.mark.parametrize("key,era", keys())
def test_live_attestation_raw(key, era):
    body = {"wallet": WALLET, "conditions": [{"type": "token_balance", "chainId": 1, "contractAddress": USDC, "operator": "gte", "threshold": "1"}]}
    res = post("/v1/attest", key, body)
    assert res.get("ok") is True, res
    expected_kid = "insumer-attest-v2" if era == "v2" else "insumer-attest-v1"
    assert res["data"]["kid"] == expected_kid, res["data"].get("kid")
    out = verify_attestation(res, jwks_url=JWKS, max_age=3600)
    assert out["valid"] is True, out
    assert out["checks"]["pq"]["status"] == "verified", out["checks"]["pq"]
    assert out["checks"]["pq"]["kid"] == "insumer-attest-pq1"
    assert "jwt" not in out["checks"]


@pytest.mark.skipif(not keys(), reason="no INSUMER_API_KEY_V1/V2 in the environment")
@pytest.mark.parametrize("key,era", keys())
def test_live_attestation_jwt_format(key, era):
    body = {"wallet": WALLET, "format": "jwt", "conditions": [{"type": "token_balance", "chainId": 1, "contractAddress": USDC, "operator": "gte", "threshold": "1"}]}
    res = post("/v1/attest", key, body)
    assert res.get("ok") is True, res
    assert isinstance(res["data"].get("jwt"), str) and isinstance(res["data"].get("pqJwt"), str)
    whole = verify_attestation(res, jwks_url=JWKS, max_age=3600)
    assert whole["valid"] is True, whole
    assert whole["checks"]["jwt"]["passed"] is True, whole["checks"]["jwt"]
    assert whole["checks"]["jwt"]["pq"]["status"] == "verified"
    token_only = verify_attestation(res["data"]["jwt"], jwks_url=JWKS, pq_jwt=res["data"]["pqJwt"])
    assert token_only["valid"] is True, token_only
    assert token_only["checks"]["pq"]["status"] == "verified"
    # The subject is the wallet a condition evaluated.
    import base64

    payload = json.loads(base64.urlsafe_b64decode(res["data"]["jwt"].split(".")[1] + "==").decode())
    assert payload["sub"].lower() == WALLET.lower()


@pytest.mark.skipif(not keys(), reason="no INSUMER_API_KEY_V1/V2 in the environment")
@pytest.mark.parametrize("key,era", keys())
def test_live_trust_profile(key, era):
    res = post("/v1/trust", key, {"wallet": WALLET})
    assert res.get("ok") is True, res
    expected_kid = "insumer-trust-v2" if era == "v2" else "insumer-attest-v1"
    assert res["data"]["kid"] == expected_kid, res["data"].get("kid")
    out = verify_trust_profile(res, jwks_url=JWKS, max_age=3600)
    assert out["valid"] is True, out
    assert out["checks"]["pq"]["status"] == "verified", out["checks"]["pq"]
    assert out["checks"]["pq"]["kid"] == "insumer-trust-pq1"
    assert out["trust"] is res["data"]["trust"]
