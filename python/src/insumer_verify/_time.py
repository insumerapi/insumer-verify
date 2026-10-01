"""Timestamps the way JavaScript's ``Date`` reads them.

The verifier compares ISO 8601 strings from the issuer against the caller's
clock and the caller's own dates. ``new Date(value)`` has rules this module
mirrors: a date-only form is UTC and a date-time form without an offset is
local time; out-of-range fields make the whole value invalid, except that a
day past the end of its month rolls over; a number is milliseconds; a boolean
is 0 or 1; an array is read through its string form. Anything JavaScript would
turn into ``NaN`` is ``None`` here, at every call site.
"""

from __future__ import annotations

import math
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from ._jsjson import js_to_string

#: The range of a JavaScript time value, in milliseconds either side of the epoch.
MAX_TIME_MS = 8_640_000_000_000_000

_ISO = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})"
    r"(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?"
    r"(Z|z|[+-]\d{2}:?\d{2})?"
)

_EPOCH = datetime(1970, 1, 1)


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 for a proleptic Gregorian date; a day past the month's end rolls over."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _clip(ms: float) -> Optional[int]:
    if math.isnan(ms) or math.isinf(ms) or abs(ms) > MAX_TIME_MS:
        return None
    return int(ms)  # truncation toward zero, as TimeClip does


def parse_iso_ms(text: str) -> Optional[int]:
    """``Date.parse`` of the ISO 8601 forms the issuer emits and callers write."""
    m = _ISO.fullmatch(text)  # fullmatch: a trailing newline is not part of a date
    if not m:
        return None
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    has_time = m.group(4) is not None
    hour = int(m.group(4) or 0)
    minute = int(m.group(5) or 0)
    second = int(m.group(6) or 0)
    frac = m.group(7) or ""
    millis = int((frac + "000")[:3]) if frac else 0
    offset = m.group(8)
    if not 1 <= month <= 12 or not 1 <= day <= 31:
        return None
    if hour > 24 or minute > 59 or second > 59:
        return None
    if hour == 24 and (minute or second or millis):
        return None
    offset_seconds = 0
    if offset and offset not in ("Z", "z"):
        digits = offset[1:].replace(":", "")
        oh, om = int(digits[:2]), int(digits[2:])
        if oh > 23 or om > 59:
            return None
        offset_seconds = (-1 if offset[0] == "-" else 1) * (oh * 3600 + om * 60)
    seconds = _days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
    if has_time and offset is None:
        # Date-time with no offset: local time, as Date.parse reads it.
        try:
            local = _EPOCH + timedelta(seconds=seconds)
            return _clip(local.timestamp() * 1000 + millis)
        except (OverflowError, ValueError, OSError):
            return None
    return _clip((seconds - offset_seconds) * 1000 + millis)


def parse_time_ms(value: Any) -> Optional[int]:
    """``new Date(value).getTime()`` for a JSON value, a datetime or a date; ``None`` where JavaScript has NaN."""
    if isinstance(value, datetime):
        return _clip(value.timestamp() * 1000)
    if isinstance(value, date):
        return _clip(_days_from_civil(value.year, value.month, value.day) * 86400 * 1000)
    if value is None:
        return 0  # new Date(null) is the epoch; callers skip falsy values before reaching here
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return _clip(float(value))
    if isinstance(value, str):
        return parse_iso_ms(value)
    if isinstance(value, (list, tuple)):
        return parse_iso_ms(js_to_string(value))
    return None


def iso_from_ms(ms: int) -> str:
    """``Date.prototype.toISOString`` for a millisecond timestamp."""
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def now_ms() -> int:
    """Current wall-clock time in milliseconds since the Unix epoch."""
    import time

    return int(time.time() * 1000)
