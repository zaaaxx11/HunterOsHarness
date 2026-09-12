"""Event-sourced, hash-chained event model — the kernel contract.

Every observable fact in a scan becomes an immutable Event appended to the
ledger. The run IS the log; transcripts and reports are views over it.

The hash chain is the tamper-evidence mechanism::

    hash_n = sha256(canonical_json({prev_hash, run_id, seq, kind, payload, ts}))

``canonical_json`` is a load-bearing format: changing it invalidates every
existing ledger. Do not change it without a migration plan.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

GENESIS_HASH = "0" * 64


class EventKind(str, Enum):
    RUN_STARTED = "run_started"
    RUN_ENDED = "run_ended"
    PHASE_STARTED = "phase_started"
    PHASE_ENDED = "phase_ended"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    PROBE_STARTED = "probe_started"
    PROBE_RESULT = "probe_result"
    EVIDENCE_STORED = "evidence_stored"
    FINDING_CREATED = "finding_created"
    FINDING_STATUS_CHANGED = "finding_status_changed"
    SCOPE_CHECK = "scope_check"
    ENGINE_EVENT = "engine_event"
    ERROR = "error"
    # v0.3 phase-machine kinds (additive only; hashing is unaffected — the
    # chain hashes the kind VALUE string, never the enum member list).
    CLASSIFICATION_RECORDED = "classification_recorded"
    REPORT_RENDERED = "report_rendered"
    RETRO_RECORDED = "retro_recorded"


def canonical_json(obj: Any) -> str:
    """Stable serialization used for hashing and evidence digests.

    Sorts keys, strips whitespace, preserves non-ASCII. Must never change.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_hash(
    prev_hash: str, run_id: str, seq: int, kind: str, payload: dict[str, Any], ts: float
) -> str:
    material = canonical_json(
        {
            "prev_hash": prev_hash,
            "run_id": run_id,
            "seq": seq,
            "kind": kind,
            "payload": payload,
            "ts": ts,
        }
    )
    return sha256_hex(material)


@dataclass(frozen=True, slots=True)
class Event:
    seq: int
    run_id: str
    kind: EventKind
    payload: dict[str, Any]
    ts: float
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        kind: EventKind | str,
        payload: dict[str, Any],
        seq: int,
        ts: float,
        prev_hash: str,
    ) -> Event:
        kind_value = kind.value if isinstance(kind, EventKind) else str(kind)
        digest = event_hash(prev_hash, run_id, seq, kind_value, payload, ts)
        return cls(
            seq=seq,
            run_id=run_id,
            kind=kind,  # type: ignore[arg-type]
            payload=payload,
            ts=ts,
            prev_hash=prev_hash,
            hash=digest,
        )

    def kind_value(self) -> str:
        return self.kind.value if isinstance(self.kind, EventKind) else str(self.kind)

    def recompute_hash(self) -> str:
        return event_hash(
            self.prev_hash, self.run_id, self.seq, self.kind_value(), self.payload, self.ts
        )

    def verify(self) -> bool:
        return self.hash == self.recompute_hash()
