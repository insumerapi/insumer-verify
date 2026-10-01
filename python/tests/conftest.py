import json
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str):
    with open(FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def vectors():
    """The published conformance vectors, as a dict keyed by vector id."""
    return load("state-attestation-test-vectors.json")["vectors"]


@pytest.fixture(scope="session")
def saved_jwks():
    """A saved copy of the issuer's JWKS: three EC entries, then two AKP entries."""
    return load("jwks.json")


@pytest.fixture
def no_network(monkeypatch):
    """Make any JWKS fetch fail loudly, so a test proves nothing was fetched."""
    calls = {"n": 0}

    def fail(url):
        calls["n"] += 1
        raise ValueError("network disabled in this test")

    import insumer_verify._keys as keys

    monkeypatch.setattr(keys, "_fetch_json", fail)
    return calls


def snake_options(options):
    """The vectors name options as the JavaScript package does; map them to Python keywords."""
    mapping = {
        "jwksUrl": "jwks_url",
        "jwks": "jwks",
        "maxAge": "max_age",
        "clockSkew": "clock_skew",
        "mode": "mode",
        "pqRequiredFrom": "pq_required_from",
        "pqActivatedAt": "pq_activated_at",
        "pqJwt": "pq_jwt",
    }
    out = {}
    for k, v in (options or {}).items():
        out[mapping[k]] = v
    return out


def is_trust_vector(vector) -> bool:
    data = vector["response"].get("data") or {}
    return "trust" in data
