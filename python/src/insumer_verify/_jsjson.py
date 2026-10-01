"""JavaScript-compatible JSON serialization.

Every preimage and condition hash InsumerAPI signs is defined by the bytes
``JSON.stringify`` produces in the issuer's runtime. Python's ``json`` module
differs from it in corners that change those bytes: how non-integral and very
large numbers are printed, the order in which object keys are emitted when some
of them look like array indexes, how keys are sorted (code units, not code
points), and how an array "replacer" filters nested objects. This module
reproduces the JavaScript behaviour exactly rather than approximating it with
``json.dumps``.

Nothing here is specific to attestations. It is the serializer the verifier
needs, kept separate so that it can be tested against known JavaScript output.
"""

from __future__ import annotations

import math
from typing import Any, List, Optional, Sequence

#: Maximum nesting depth this verifier will canonicalize.
#:
#: Canonicalization runs alongside signature verification, not after it, so the
#: recursive walk below is reachable by anyone holding an artifact: a signature
#: does not have to be valid to get here. 128 open containers matches the bound
#: the JavaScript reference verifier applies, so a verifier that refuses here
#: refuses what it refuses. The deepest artifact in the published conformance
#: corpus nests 9 levels.
MAX_CANONICAL_DEPTH = 128


class CanonicalDepthError(ValueError):
    """Raised when an artifact nests past :data:`MAX_CANONICAL_DEPTH`.

    Callers turn this into a failed check: it is a refusal to verify, never a
    passing verdict.
    """

    def __init__(self, limit: int = MAX_CANONICAL_DEPTH) -> None:
        super().__init__(f"Artifact nests deeper than {limit} levels; refusing to canonicalize")
        self.limit = limit


# ── Strings ──────────────────────────────────────────────────────────

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def js_string(s: str) -> str:
    """``JSON.stringify`` of a string.

    Escapes the quote, the backslash, the five short control escapes, every
    other control character below U+0020 as ``\\u00xx`` (lowercase hex), and a
    lone surrogate as ``\\udxxx`` (well-formed ``JSON.stringify``, ES2019).
    Everything else, including non-ASCII text, is emitted as-is.
    """
    out: List[str] = ['"']
    for ch in s:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
            continue
        o = ord(ch)
        if o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ── Numbers ──────────────────────────────────────────────────────────

_MAX_SAFE_INTEGER = 2**53


def js_number(n: Any) -> str:
    """``JSON.stringify`` of a number: ECMAScript ``Number::toString`` in base 10.

    Integers up to 2**53 print as themselves. Anything else is treated as the
    IEEE double JavaScript would hold, printed with the shortest digit string
    that round-trips, in plain decimal notation for exponents between -7 and
    21 and in ``d.ddde+xx`` form outside that range. NaN and the infinities
    print as ``null``, as ``JSON.stringify`` does.
    """
    if isinstance(n, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(n, int):
        if abs(n) < _MAX_SAFE_INTEGER:
            return str(n)
        n = float(n)
    if not isinstance(n, float):
        raise TypeError(f"not a number: {type(n).__name__}")
    if math.isnan(n) or math.isinf(n):
        return "null"
    if n == 0:
        return "0"  # JavaScript prints -0 as "0"

    sign = "-" if n < 0 else ""
    text = repr(abs(n))  # shortest round-trip digits
    if "e" in text:
        mantissa, exp_text = text.split("e")
        exponent = int(exp_text)
    else:
        mantissa, exponent = text, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    digits = int_part + frac_part
    exponent -= len(frac_part)  # value = int(digits) * 10**exponent
    digits = digits.lstrip("0")
    stripped = len(digits) - len(digits.rstrip("0"))
    digits = digits[: len(digits) - stripped] if stripped else digits
    exponent += stripped
    k = len(digits)  # number of significant digits
    pos = k + exponent  # ECMAScript "n": value = 0.digits * 10**pos

    if k <= pos <= 21:
        return sign + digits + "0" * (pos - k)
    if 0 < pos <= 21:
        return sign + digits[:pos] + "." + digits[pos:]
    if -6 < pos <= 0:
        return sign + "0." + "0" * (-pos) + digits
    e = pos - 1
    e_text = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + e_text
    return sign + digits[0] + "." + digits[1:] + "e" + e_text


# ── Property order ───────────────────────────────────────────────────


def _is_array_index(key: str) -> bool:
    # A canonical numeric string below 2**32 - 1: ASCII digits, no leading zero
    # (except "0" itself), and in range.
    if not key or not key.isascii() or not key.isdigit():
        return False
    if len(key) > 1 and key[0] == "0":
        return False
    return int(key) < 2**32 - 1


def js_keys(obj: dict) -> List[str]:
    """``Object.keys`` order: integer-like keys ascending, then the rest in insertion order.

    ``JSON.parse`` applies the same rule, so a verifier that reproduces an
    insertion-order preimage must honour it even though ordinary attestation
    fields never look like array indexes.
    """
    indexes: List[str] = []
    rest: List[str] = []
    for key in obj:
        if not isinstance(key, str):
            raise TypeError("JSON object keys must be strings")
        (indexes if _is_array_index(key) else rest).append(key)
    indexes.sort(key=int)
    return indexes + rest


def utf16_sort_key(key: str) -> bytes:
    """Sort key reproducing the default ``Array.prototype.sort`` on strings.

    JavaScript compares strings by UTF-16 code units. For characters outside the
    Basic Multilingual Plane that order differs from Python's code-point order,
    so the keys are compared as big-endian UTF-16 bytes instead.
    """
    return key.encode("utf-16-be", "surrogatepass")


# ── Serializers ──────────────────────────────────────────────────────


def js_stringify(value: Any, depth: int = 0, allow: Optional[Sequence[str]] = None) -> str:
    """``JSON.stringify(value)`` or, with ``allow``, ``JSON.stringify(value, allow)``.

    With an allow list (JavaScript's array replacer) every object at every
    nesting level emits only the listed properties, in the list's order. Depth
    is bounded by :data:`MAX_CANONICAL_DEPTH`.
    """
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalDepthError()
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_stringify(v, depth + 1, allow) for v in value) + "]"
    if isinstance(value, dict):
        if allow is None:
            keys: Sequence[str] = js_keys(value)
        else:
            keys = [k for k in allow if k in value]
        parts = [js_string(k) + ":" + js_stringify(value[k], depth + 1, allow) for k in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"cannot serialize {type(value).__name__}")


def canonicalize(value: Any, depth: int = 0) -> str:
    """Canonical JSON as the v2 signing scheme defines it.

    Arrays keep their order and canonicalize each element; objects emit their
    keys sorted as JavaScript sorts them (UTF-16 code units), each as
    ``JSON.stringify(key) + ":" + canonicalize(value)``; every other value is
    ``JSON.stringify(value)``. No whitespace. The sort applies at every nesting
    level. Depth is bounded by :data:`MAX_CANONICAL_DEPTH`.
    """
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalDepthError()
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(js_keys(value), key=utf16_sort_key)
        return "{" + ",".join(js_string(k) + ":" + canonicalize(value[k], depth + 1) for k in keys) + "}"
    return js_stringify(value)


def assert_depth(value: Any, depth: int = 0) -> None:
    """Depth check for the v1 (bare JSON) paths.

    v1 preimages are frozen, so the serializer must not alter their bytes. This
    walks the value only to enforce the same bound the v2 path enforces.
    """
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalDepthError()
    if isinstance(value, (list, tuple)):
        for v in value:
            assert_depth(v, depth + 1)
    elif isinstance(value, dict):
        for v in value.values():
            assert_depth(v, depth + 1)


def js_object_keys(value: Any) -> List[str]:
    """``Object.keys(value)`` for any JSON value: an array yields its indexes, a primitive nothing."""
    if isinstance(value, dict):
        return js_keys(value)
    if isinstance(value, (list, tuple)):
        return [str(i) for i in range(len(value))]
    return []


def v1_condition_canonical(evaluated_condition: Any) -> str:
    """``JSON.stringify(evaluatedCondition, Object.keys(evaluatedCondition).sort())``.

    The v1 condition-hash preimage. The sorted top-level key list is passed as
    the replacer array, so top-level keys come out sorted, and a nested object
    (none exists in a real v1 condition) would be filtered to those same names.
    A value that is not an object is serialized the way ``JSON.stringify`` would
    serialize it with that replacer, so the two verifiers agree on every shape.
    """
    assert_depth(evaluated_condition)
    allow = sorted(js_object_keys(evaluated_condition), key=utf16_sort_key)
    return js_stringify(evaluated_condition, allow=allow)


# ── Structural comparison ────────────────────────────────────────────


def _same_primitive(a: Any, b: Any) -> bool:
    # JavaScript strict equality on JSON primitives: a boolean never equals a
    # number (Python's True == 1 must not leak in), numbers compare by value,
    # strings and null by identity of kind and value.
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if a is None or b is None:
        return a is None and b is None
    return isinstance(a, str) and isinstance(b, str) and a == b


def first_claim_difference(a: Any, b: Any, path: str = "", depth: int = 0) -> Optional[str]:
    """First path at which two parsed JSON values differ, or ``None`` when deeply equal.

    Objects are compared without regard to member order, arrays in order,
    primitives by value; a member present on one side only is a difference.
    Depth-bounded like every other walker here.
    """
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalDepthError()
    a_obj = isinstance(a, (dict, list, tuple))
    b_obj = isinstance(b, (dict, list, tuple))
    if not a_obj and not b_obj:
        return None if _same_primitive(a, b) else path
    if not a_obj or not b_obj:
        return path
    a_arr = isinstance(a, (list, tuple))
    b_arr = isinstance(b, (list, tuple))
    if a_arr != b_arr:
        return path
    if a_arr:
        if len(a) != len(b):
            return path
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_claim_difference(x, y, f"{path}[{i}]", depth + 1)
            if d is not None:
                return d
        return None
    for k in js_keys(a):
        if k not in b:
            return f"{path}.{k}" if path else k
    for k in js_keys(b):
        if k not in a:
            return f"{path}.{k}" if path else k
    for k in js_keys(a):
        d = first_claim_difference(a[k], b[k], f"{path}.{k}" if path else k, depth + 1)
        if d is not None:
            return d
    return None
