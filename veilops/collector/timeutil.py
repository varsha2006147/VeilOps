from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


def parse_ts(value, default_tz: str = "UTC") -> datetime:
    """Parse epoch seconds/ms or ISO-8601 into an aware UTC datetime.

    Naive timestamps are interpreted in the source's own zone (default_tz), then converted to UTC.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        secs = value / 1000.0 if value > 1e11 else float(value)
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    else:
        s = str(value).strip()
        if s.replace(".", "", 1).isdigit():
            return parse_ts(float(s), default_tz)
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(default_tz))
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def floor_ts(dt: datetime, window_s: int) -> datetime:
    epoch = dt.timestamp()
    return datetime.fromtimestamp(epoch - (epoch % window_s), tz=timezone.utc)
