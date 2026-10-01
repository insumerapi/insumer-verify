"""Timestamps the way JavaScript's ``Date`` reads them.

The verifier compares ISO 8601 strings from the issuer against the caller's
clock and the caller's own dates. ``Date.parse`` accepts a date-only form as
UTC and a date-time form without an offset as local time; this module mirrors
that so a cutoff a caller writes behaves the same in both verifiers. Anything
unparsable is ``None`` where JavaScript would have ``NaN``.
"""

from __future__ import annotations

import calendar
import re
import time
from datetime import date, datetime, timezone
from typing import Any, Optional

_ISO = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})"
    r"(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?)?"
    r"\s*(Z|z|[+-]\d{2}:?\d{2})?\s*$"
)


def now_ms() -> int:
    """Current wall-clock time in milliseconds since the Unix epoch."""
    return int(time.time() * 1000)


def parse_time_ms(value: Any) -> Optional[int]:
    """Milliseconds since the epoch for an ISO 8601 string, a datetime, or a number.

    Returns ``None`` when the value cannot be read as a time, which is what the
    checks treat as JavaScript's ``NaN``.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return int(value.timestamp() * 1000)
    if isinstance(value, date):
        return int(calendar.timegm(value.timetuple()) * 1000)
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return None
    m = _ISO.match(value)
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
    try:
        if not has_time or offset is not None:
            # Date-only is UTC; an explicit offset is applied.
            base = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
            if offset and offset not in ("Z", "z"):
                sign = -1 if offset[0] == "-" else 1
                digits = offset[1:].replace(":", "")
                base -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
            return base * 1000 + millis
        # Date-time with no offset: local time, as Date.parse reads it.
        local = datetime(year, month, day, hour, minute, second)
        return int(local.timestamp() * 1000) + millis
    except (ValueError, OverflowError):
        return None


def iso_from_ms(ms: int) -> str:
    """``Date.prototype.toISOString`` for a millisecond timestamp."""
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
