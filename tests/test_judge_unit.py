"""Judge Mode pure measurement logic (no PostgreSQL/Redis needed)."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from cloud.app import judge

T0 = datetime(2026, 11, 21, 4, 0, tzinfo=timezone.utc)


# 1. p50 / p95 / max --------------------------------------------------------------

def test_percentiles_match_postgres_percentile_cont():
    values = list(range(1, 101))  # 1..100
    out = judge.percentiles(values)
    # PostgreSQL percentile_cont gives 50.5 and 95.05; values are reported to 0.1 ms.
    assert out == {"count": 100, "p50_ms": 50.5, "p95_ms": round(95.05, 1), "max_ms": 100.0}


def test_percentiles_single_and_unsorted():
    assert judge.percentiles([7]) == {"count": 1, "p50_ms": 7.0, "p95_ms": 7.0, "max_ms": 7.0}
    assert judge.percentiles([300, 100, 200])["p50_ms"] == 200.0


def test_percentiles_empty_and_invalid_values():
    empty = {"count": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}
    assert judge.percentiles([]) == empty
    assert judge.percentiles([None, float("nan"), float("inf")]) == empty


def test_target_status():
    assert judge.target_status(None, 10_000) == "insufficient_data"
    assert judge.target_status(10_000, 10_000) == "pass"
    assert judge.target_status(10_001, 10_000) == "fail"


# 3. breach detection (pure part) ---------------------------------------------------

def _w(sec, lo, hi):
    return (T0 + timedelta(seconds=sec), lo, hi)


def test_first_breach_is_start_of_contiguous_breaching_run():
    newest_first = [_w(15, 90, 97), _w(10, 88, 96), _w(5, 60, 91), _w(0, 20, 30), _w(-5, 92, 95)]
    # The older breach at -5 s is separated by a calm window and must not be used.
    assert judge.first_breach_ts(newest_first, 90.0, below=False) == T0 + timedelta(seconds=5)


def test_first_breach_below_threshold_rule():
    newest_first = [_w(10, 0, 0), _w(5, 0, 1), _w(0, 1, 1)]
    assert judge.first_breach_ts(newest_first, 0.5, below=True) == T0 + timedelta(seconds=5)


def test_no_breach_is_never_invented():
    assert judge.first_breach_ts([_w(5, 10, 20), _w(0, 10, 20)], 90.0, below=False) is None
    assert judge.first_breach_ts([], 90.0, below=False) is None


# 5. missing sequences ---------------------------------------------------------------

def test_missing_sequences():
    assert judge.missing_sequences(1, 6, {1, 2, 4, 6}) == [3, 5]
    assert judge.missing_sequences(1, 3, {1, 2, 3}) == []


# 8. backlog drain ------------------------------------------------------------------

def test_backlog_episode_drain_duration():
    hb = [(T0, 0), (T0 + timedelta(seconds=40), 12), (T0 + timedelta(seconds=45), 4),
          (T0 + timedelta(seconds=52), 0), (T0 + timedelta(seconds=60), 0)]
    (ep,) = judge.backlog_episodes(hb)
    assert ep["peak_depth"] == 12 and ep["drain_ms"] == 12_000


def test_backlog_still_draining_has_no_duration():
    (ep,) = judge.backlog_episodes([(T0, 3), (T0 + timedelta(seconds=5), 2)])
    assert ep["drain_ms"] is None and ep["drained_at"] is None


# 10. CSV safety --------------------------------------------------------------------

def test_csv_cells_cannot_start_a_formula():
    assert judge.csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert judge.csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert judge.csv_safe("h_7f3a21c90b") == "h_7f3a21c90b"
    assert judge.csv_safe(None) == ""


# 11. invalid record keys ----------------------------------------------------------

@pytest.mark.parametrize("key,ok", [
    ("payload:0196b8f2-1111-7abc-8def-0123456789ab", True),
    ("alert:0196b8f2-1111-7abc-8def-0123456789ab", True),
    ("metric:h_7f3a21c90b|cpu.util_pct|2026-11-21T04:00:00Z", True),
    ("payload:not-a-uuid", False),
    ("metric:h_x|cpu|2026-11-21T04:00:00Z;DROP TABLE", False),
    ("source_event_ts:2026-11-21T04:00:00Z", False),
])
def test_record_key_validation(key, ok):
    assert bool(judge.RECORD_KEY_RE.match(key)) is ok


# 12. PostgreSQL failure: the background measurement loop survives and keeps running --

class _BrokenPool:
    def __init__(self):
        self.calls = 0

    def acquire(self):
        self.calls += 1
        raise OSError("connection refused")


async def test_judge_loop_survives_database_outage():
    pool, stop = _BrokenPool(), asyncio.Event()
    task = asyncio.create_task(judge.judge_loop(pool, interval_seconds=0.01, stop_event=stop))
    await asyncio.sleep(0.08)
    stop.set()
    await asyncio.wait_for(task, 1)
    assert pool.calls >= 2  # retried after the failure instead of crashing
