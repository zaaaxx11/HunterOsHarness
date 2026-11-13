"""The PII circuit breaker is the rule a prompt cannot be trusted to keep.

A live hunt against a real target hit this in production: phase0 recon of
honest.co.id produced a response containing 16 consecutive digits, the breaker
tripped, LLM was skipped, and the hunt continued on the deterministic path.
Without it that byte would have gone straight into the model's context.
"""
from __future__ import annotations

import pytest

from hunter.workflow.pii_guard import PIITriggered, scan, scrub


@pytest.mark.parametrize("payload,kind", [
    ("4111111111111111", "card-16"),
    ("4111 1111 1111 1111", "card-grouped"),
    ("378282246310005", "amex-15"),
    ("123-45-6789", "ssn-like"),
    ("NIK: 3201234567890001", "nik-labeled"),
    ("3201234567890001 | Budi Santoso", "nik-row"),
    ("KTP 3201234567890001", "gov-id-labeled"),
    ("user@example.com", "email"),
    ("+62 812-3456-7890", "phone-id"),
])
def test_real_user_data_trips_the_breaker(payload, kind):
    with pytest.raises(PIITriggered) as exc:
        scan(payload)
    assert exc.value.kind == kind


@pytest.mark.parametrize("clean", [
    '{"status":"ok"}',
    "<script src=\"/static/js/app.9f2a1c.js\"></script>",
    "404 page not found",
    "{\"page\": 1, \"total\": 42}",
    "order-2024-000123",
    "0x" + "ab" * 20,
    "",
])
def test_benign_payloads_never_trip(clean):
    scan(clean)  # must not raise


def test_scrub_makes_a_stop_loggable():
    text = "card 4111111111111111 for user@example.com"
    out = scrub(text)
    assert "4111111111111111" not in out
    assert "user@example.com" not in out
    assert "[REDACTED:" in out


def test_scan_is_deterministic_and_stops_at_first_match():
    # labelled NIK wins over the bare card rule — the stop reason must say what
    # was actually found, not the first blanket pattern that also matches
    with pytest.raises(PIITriggered) as exc:
        scan("NIK: 3201234567890001 alongside 4111111111111111")
    assert exc.value.kind == "nik-labeled"
    with pytest.raises(PIITriggered) as exc:
        scan("3201234567890001 | Budi Santoso and 4111-1111-1111-1111")
    assert exc.value.kind == "nik-row"


def test_non_string_input_never_raises():
    for value in (None, 0, b"bytes", [], {}):
        scan(value)  # type: ignore[arg-type]


def test_excerpt_is_short_enough_to_log():
    try:
        scan("x" * 5000 + " 4111111111111111")
    except PIITriggered as exc:
        assert len(exc.excerpt) <= 200
    else:
        raise AssertionError("should have tripped")
