"""Tests for hunter.engine.signals classifier."""

from __future__ import annotations

import httpx

from hunter.engine.signals import (
    RATELIMIT_MARKERS,
    SOFT404_MARKERS,
    WAF_MARKERS,
    SignalClass,
    classify,
    is_ratelimit,
    is_soft_404,
    is_waf,
)


def test_error_transport():
    assert classify(200, {}, "ok", error=httpx.ConnectError("connect timeout")) == SignalClass.TRANSPORT


def test_error_crash():
    assert classify(200, {}, "ok", error=ValueError("boom")) == SignalClass.CRASH


def test_waf_marker_case_insensitive():
    assert classify(403, {"Server": "CloudFlare"}, "ACCESS DENIED") == SignalClass.WAF
    assert is_waf(403, {}, "access denied") is True
    assert is_waf(403, {}, "ACCESS DENIED") is True


def test_waf_empty_short_body():
    assert classify(403, {}, "") == SignalClass.WAF
    assert is_waf(403, {}, "   ") is True


def test_ratelimit_429():
    assert classify(429, {}, "anything") == SignalClass.RATELIMIT
    assert is_ratelimit(429, {}, "") is True


def test_ratelimit_marker():
    assert classify(200, {}, "Rate Limit exceeded") == SignalClass.RATELIMIT
    assert is_ratelimit(200, {}, "too many requests") is True


def test_soft404_status():
    assert classify(404, {}, "gone") == SignalClass.SOFT_404
    assert is_soft_404(404, {}, "") is True


def test_soft404_marker():
    assert classify(200, {}, "Page not found") == SignalClass.SOFT_404
    assert is_soft_404(200, {}, "not found") is True


def test_canary_signal():
    assert classify(200, {}, "body with CANARY here", canary="CANARY") == SignalClass.SIGNAL


def test_status_diff_signal():
    assert (
        classify(500, {}, "err", baseline_status=200, baseline_body="ok") == SignalClass.SIGNAL
    )


def test_body_diff_signal():
    base = "a" * 100
    body = "a" * 120
    assert classify(200, {}, body, baseline_status=200, baseline_body=base) == SignalClass.SIGNAL


def test_ambiguous_small_diff():
    base = "a" * 100
    body = "a" * 105
    assert classify(200, {}, body, baseline_status=200, baseline_body=base) == SignalClass.AMBIGUOUS


def test_clean_identical():
    base = "hello world"
    assert classify(200, {}, base, baseline_status=200, baseline_body=base) == SignalClass.CLEAN


def test_clean_no_baseline():
    assert classify(200, {}, "ok") == SignalClass.CLEAN


def test_helpers_waf():
    assert is_waf(406, {}, "waf block") is True
    assert is_waf(200, {}, "waf") is False


def test_markers_frozen():
    assert isinstance(WAF_MARKERS, frozenset)
    assert isinstance(RATELIMIT_MARKERS, frozenset)
    assert isinstance(SOFT404_MARKERS, frozenset)


def test_all_classes_represented():
    # sanity: 8 distinct values
    assert len(set(SignalClass)) == 8
    assert {m.value for m in SignalClass} == {
        "clean",
        "signal",
        "ambiguous",
        "waf",
        "soft-404",
        "ratelimit",
        "transport",
        "crash",
    }
