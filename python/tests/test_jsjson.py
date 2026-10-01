"""The serializer must reproduce JavaScript's JSON.stringify byte for byte.

Expected strings below are what Node.js prints. ``test_matches_node`` re-derives
them live when a ``node`` binary is on the PATH, so the table cannot rot.
"""

import json
import shutil
import subprocess

import pytest

from insumer_verify._jsjson import (
    MAX_CANONICAL_DEPTH,
    CanonicalDepthError,
    assert_depth,
    canonicalize,
    first_claim_difference,
    js_keys,
    js_number,
    js_string,
    js_stringify,
    utf16_sort_key,
    v1_condition_canonical,
)

NUMBERS = [
    (0, "0"),
    (-0.0, "0"),
    (1, "1"),
    (1.0, "1"),
    (1.5, "1.5"),
    (0.001, "0.001"),
    (0.000001, "0.000001"),
    (1e-7, "1e-7"),
    (1.5e-7, "1.5e-7"),
    (123456789012345680000.0, "123456789012345680000"),
    (1e21, "1e+21"),
    (1.2345e21, "1.2345e+21"),
    (2**53, "9007199254740992"),
    (2**53 - 1, "9007199254740991"),
    (12345678901234567890, "12345678901234567000"),
    (-42.25, "-42.25"),
    (100.0, "100"),
    (0.1 + 0.2, "0.30000000000000004"),
]


@pytest.mark.parametrize("value,expected", NUMBERS)
def test_numbers(value, expected):
    assert js_number(value) == expected


def test_non_finite_numbers_are_null():
    assert js_number(float("nan")) == "null"
    assert js_number(float("inf")) == "null"


STRINGS = [
    ("plain", '"plain"'),
    ('quote " and backslash \\', '"quote \\" and backslash \\\\"'),
    ("tab\tnewline\ncr\r", '"tab\\tnewline\\ncr\\r"'),
    ("\x00\x1f", '"\\u0000\\u001f"'),
    ("é ✓ 😀", '"é ✓ 😀"'),
    ("  ", '"  "'),
    ("\ud800", '"\\ud800"'),
]


@pytest.mark.parametrize("value,expected", STRINGS)
def test_strings(value, expected):
    assert js_string(value) == expected


def test_property_order_puts_array_indexes_first():
    obj = {"b": 1, "10": 2, "a": 3, "2": 4, "007": 5, "-1": 6}
    assert js_keys(obj) == ["2", "10", "b", "a", "007", "-1"]
    assert js_stringify(obj) == '{"2":4,"10":2,"b":1,"a":3,"007":5,"-1":6}'


def test_sort_is_by_utf16_code_units_not_code_points():
    # U+1F600 is encoded as the surrogate pair D83D DE00, so JavaScript sorts it
    # BEFORE U+FB01, while Python's default string order puts it after.
    keys = ["ﬁ", "\U0001F600", "a"]
    assert sorted(keys, key=utf16_sort_key) == ["a", "\U0001F600", "ﬁ"]
    assert sorted(keys) == ["a", "ﬁ", "\U0001F600"]
    assert canonicalize({"ﬁ": 1, "\U0001F600": 2}) == '{"\U0001F600":2,"ﬁ":1}'


def test_canonicalize_sorts_at_every_level_and_keeps_array_order():
    value = {"z": [{"b": 1, "a": 2}, 3], "a": {"y": None, "x": True}}
    assert canonicalize(value) == '{"a":{"x":true,"y":null},"z":[{"a":2,"b":1},3]}'


def test_v1_condition_canonical_uses_the_replacer_semantics():
    flat = {"type": "token_balance", "chainId": 1, "threshold": 1, "decimals": 6}
    assert v1_condition_canonical(flat) == '{"chainId":1,"decimals":6,"threshold":1,"type":"token_balance"}'
    # A replacer array applies at every level: the nested object is filtered to
    # the top-level key names, in the list's order.
    nested = {"b": {"a": 1, "zzz": 2, "b": 3}, "a": 0}
    assert v1_condition_canonical(nested) == '{"a":0,"b":{"a":1,"b":3}}'


def test_depth_bound_accepts_at_the_bound_and_refuses_one_past():
    def nested(n):
        v = []
        for _ in range(n - 1):
            v = [v]
        return v

    at_bound = nested(MAX_CANONICAL_DEPTH + 1)  # containers at depths 0..128
    assert canonicalize(at_bound)
    assert js_stringify(at_bound)
    assert_depth(at_bound)
    past = nested(MAX_CANONICAL_DEPTH + 2)
    for fn in (canonicalize, js_stringify, assert_depth):
        with pytest.raises(CanonicalDepthError):
            fn(past)
    # Objects as well as arrays, and the depth is not confused with a list index.
    deep_obj = {"k": None}
    for _ in range(MAX_CANONICAL_DEPTH + 1):
        deep_obj = {"k": deep_obj}
    with pytest.raises(CanonicalDepthError):
        canonicalize(deep_obj)


def test_first_claim_difference_uses_strict_equality():
    assert first_claim_difference({"a": 1}, {"a": 1}) is None
    assert first_claim_difference({"a": True}, {"a": 1}) == "a"
    assert first_claim_difference({"a": 1}, {"a": 1.0}) is None
    assert first_claim_difference({"a": [1, {"b": 2}]}, {"a": [1, {"b": 3}]}) == "a[1].b"
    assert first_claim_difference({"a": 1}, {"a": 1, "b": 2}) == "b"
    assert first_claim_difference({"a": 1, "b": 2}, {"b": 2, "a": 1}) is None
    assert first_claim_difference([1, 2], [1]) == ""
    assert first_claim_difference(None, None) is None
    assert first_claim_difference("x", None) == ""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not on PATH")
def test_matches_node():
    """Cross-check the number table and a mixed document against the real JSON.stringify."""
    doc = {
        "s": "quote \" tab\t é 😀 \x01",
        "n": [0, 1.5, 0.000001, 1e-7, 1e21, 123456789012345680000.0, 2**53, -42.25, 100.0],
        "o": {"b": 1, "10": 2, "a": 3, "2": 4},
        "t": True,
        "z": None,
    }
    script = (
        "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{"
        "const v=JSON.parse(s);"
        "const out={plain:JSON.stringify(v),"
        "nums:v.n.map(x=>JSON.stringify(x)),"
        "replacer:JSON.stringify({b:{a:1,zzz:2,b:3},a:0},['a','b'])};"
        "process.stdout.write(JSON.stringify(out));});"
    )
    res = subprocess.run(["node", "-e", script], input=json.dumps(doc), capture_output=True, text=True, check=True)
    node = json.loads(res.stdout)
    assert js_stringify(doc) == node["plain"]
    assert [js_number(x) for x in doc["n"]] == node["nums"]
    assert v1_condition_canonical({"b": {"a": 1, "zzz": 2, "b": 3}, "a": 0}) == node["replacer"]
