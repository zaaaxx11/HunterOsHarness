#!/usr/bin/env bash
# Daily retention sweep for the HunterOS ledger and chat store.
#
# Safety model (docs/RETENTION-SPEC.md, Part B):
#   * Runs that are still open are NEVER touched, at any age. Retention is an
#     attack surface for an active hunt, so the sweep must not be able to
#     erase the evidence of one in progress.
#   * Every purge is preceded by an archive whose hash chain is re-verified.
#     A failed verification rolls back and leaves live rows intact.
#   * Failure is loud. A cron job that silently stops collecting is worse than
#     one that never ran, because the disk fills while the log says "ok".
#
# Install (daily 04:15):
#   15 4 * * * /home/ubuntu/HunterOsHarness/scripts/hunter_gc_cron.sh >> ~/.hunter/gc.log 2>&1

set -euo pipefail

HUNTER_HOME="${HUNTER_HOME:-$HOME/HunterOsHarness}"
VENV_PY="${HUNTER_GC_PYTHON:-$HOME/.hunteros/venv/bin/python}"
STATE="${HUNTER_STATE_DIR:-$HOME/.hunter}"
RUN_DAYS="${HUNTER_GC_RUN_DAYS:-30}"
CHAT_DAYS="${HUNTER_GC_CHAT_DAYS:-7}"

log() { printf '%s hunter-gc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

if [ ! -x "$VENV_PY" ]; then
  log "FATAL: python not found at $VENV_PY"
  exit 1
fi

cd "$HUNTER_HOME"

# Machine-pure JSON on stdout so the log is greppable; exit code is the signal.
if ! OUT="$("$VENV_PY" -m hunter.cli.main gc \
        --state "$STATE" \
        --run-days "$RUN_DAYS" \
        --chat-days "$CHAT_DAYS" \
        --apply --json 2>&1)"; then
  log "FAILED: $OUT"
  exit 1
fi

log "ok $OUT"
