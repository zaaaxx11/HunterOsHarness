#!/usr/bin/env bash
# Background hunt: Totalcoin API surface, deeper endpoint coverage.
set -u
export DEVORA_API_KEY="${DEVORA_API_KEY:?set DEVORA_API_KEY env before running}"
export HUNTEROS_STATE_DIR="${1:?usage: tc_hunt.sh <state_dir>}"
export PYTHONPATH="${HUNTEROS_SRC:-/home/simon/HunterOsHarness/src}:${PYTHON_USER_SITE:-/home/simon/.local/lib/python3.11/site-packages}"
cd "${HUNTEROS_REPO:-/home/simon/HunterOsHarness}"
exec /usr/bin/python3 -m hunter.cli.main hunt \
  https://api.totalcoin.io/user \
  https://api.totalcoin.io/wallet \
  https://api.totalcoin.io/order \
  https://api.totalcoin.io/auth \
  https://api.totalcoin.io/market \
  https://api.totalcoin.io/login \
  --engine llm --time 5000 --state "$HUNTEROS_STATE_DIR" --yes
