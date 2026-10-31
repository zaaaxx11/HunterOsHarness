"""Bug-class taxonomy — the vocabulary of what may be claimed.

A ``klass`` is a stable bug-class id (e.g. ``reflected-xss``). Every finding
carries one; the claim gate (RULE-E5) rejects unknown klasses. Each class
bundles the anti-fabrication substance (minimum proof, common N/A patterns,
overclaim traps) ported from triager-grade report practice, so the hunter
and the agent share one definition of "what counts as this bug".

Data lives in ``_data/taxonomy/klasses.json`` (package data). Loaded lazily
and cached.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = [
    "CHECK_KLASS",
    "KLASS_IDS",
    "klass_for_check_id",
    "load_klasses",
    "validate_klass",
]

_DATA_PATH = Path(__file__).resolve().parent / "_data" / "taxonomy" / "klasses.json"

_REQUIRED_FIELDS = (
    "id",
    "label",
    "cwe_primary",
    "cwe_related",
    "lane",
    "severity_hint",
    "description",
    "falsifier_hint",
    "minimum_proof",
    "na_patterns",
    "overclaim_traps",
    "check_ids",
)
_VALID_LANES = {"web2", "web3", "network"}

_cache: dict[str, dict[str, Any]] | None = None
_CHECK_KLASS: dict[str, str] | None = None


def _validate_entry(entry: dict[str, Any]) -> None:
    for field_name in _REQUIRED_FIELDS:
        if field_name not in entry:
            raise ValueError(f"klasses.json entry missing field {field_name!r}: {entry!r}")
    klass_id = entry["id"]
    if not isinstance(klass_id, str) or not klass_id or not klass_id[0].isalnum():
        raise ValueError(f"invalid klass id {klass_id!r}")
    if entry["lane"] not in _VALID_LANES:
        raise ValueError(f"invalid lane {entry['lane']!r} for klass {klass_id!r}")
    cwe = entry["cwe_primary"]
    if not (isinstance(cwe, str) and cwe.startswith("CWE-") and cwe[4:].isdigit()):
        raise ValueError(f"invalid cwe_primary {cwe!r} for klass {klass_id!r}")
    if not isinstance(entry["cwe_related"], list):
        raise ValueError(f"cwe_related must be a list for klass {klass_id!r}")
    if not isinstance(entry["na_patterns"], list):
        raise ValueError(f"na_patterns must be a list for klass {klass_id!r}")
    if not isinstance(entry["overclaim_traps"], list):
        raise ValueError(f"overclaim_traps must be a list for klass {klass_id!r}")
    if not isinstance(entry["check_ids"], list):
        raise ValueError(f"check_ids must be a list for klass {klass_id!r}")
    for text_field in ("falsifier_hint", "minimum_proof", "description", "label"):
        if not str(entry[text_field]).strip():
            raise ValueError(f"empty {text_field} for klass {klass_id!r}")


def load_klasses(data_path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load and validate the taxonomy. Cached for the default path."""
    global _cache, _CHECK_KLASS
    path = Path(data_path) if data_path is not None else _DATA_PATH
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("klasses.json must be a JSON array")
    result: dict[str, dict[str, Any]] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("klasses.json entries must be objects")
        _validate_entry(entry)
        klass_id = entry["id"]
        if klass_id in result:
            raise ValueError(f"duplicate klass id {klass_id!r}")
        result[klass_id] = entry
    if data_path is None:
        _cache = result
        _CHECK_KLASS = None  # rebuilt lazily
    return result


def _ensure_loaded() -> dict[str, dict[str, Any]]:
    global _cache
    if _cache is None:
        _cache = load_klasses()
    return _cache


def validate_klass(klass: str) -> bool:
    """Return True when klass is a known taxonomy id or 'unknown'."""
    if klass == "unknown":
        return True
    try:
        return klass in _ensure_loaded()
    except Exception:
        return False


def klass_for_check_id(check_id: str) -> str:
    """Map a probe check_id to its owning klass id (or 'unknown')."""
    global _CHECK_KLASS
    if _CHECK_KLASS is None:
        mapping: dict[str, str] = {}
        for klass_id, entry in _ensure_loaded().items():
            for cid in entry.get("check_ids", []):
                mapping[str(cid)] = klass_id
        _CHECK_KLASS = mapping
    return _CHECK_KLASS.get(str(check_id), "unknown")


# Convenience: module-level CHECK_KLASS dict (lazy proxy via function). Exposed
# as a dict populated on first access.
try:
    _loaded = _ensure_loaded()
    CHECK_KLASS = {}
    for _klass_id, _entry in _loaded.items():
        for _cid in _entry.get("check_ids", []):
            CHECK_KLASS[str(_cid)] = _klass_id
    KLASS_IDS = frozenset(_loaded.keys()) | {"unknown"}
except Exception:
    CHECK_KLASS = {}
    KLASS_IDS = frozenset({"unknown"})
