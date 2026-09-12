#!/usr/bin/env bash
# HunterOs Harness installer for macOS / Linux.
#
# Creates a dedicated virtualenv at ~/.hunteros/venv and installs the harness:
#   1. If this script lives inside a checkout (pyproject.toml next to it),
#      installs that checkout editable:  pip install -e <checkout>
#   2. Otherwise tries PyPI:           pip install hunteros-harness
#   3. Otherwise falls back to:        pip install git+<REPO_URL>
#
# Usage:
#   ./install.sh
#   ./install.sh https://github.com/OWNER/HunterOsHarness.git
#
# Idempotent: re-running reuses the venv and refreshes the installation.
set -euo pipefail

REPO_URL="${1:-${INSTALL_REPO_URL:-https://github.com/OWNER/HunterOsHarness.git}}"
VENV_DIR="$HOME/.hunteros/venv"

step() { printf '\033[36m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[32m%s\033[0m\n' "$1"; }
fail() { printf '\n\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

echo
echo "HunterOs Harness installer"
echo "evidence or nothing"
echo

# --- 1. Locate a Python >= 3.10 ---------------------------------------------
PYTHON_EXE=""
PYTHON_ARGS=()
PYTHON_LABEL=""

python_at_least_310() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if python_at_least_310 "$candidate"; then
            PYTHON_EXE="$candidate"
            PYTHON_LABEL="$("$candidate" --version 2>&1 | head -n1)"
            break
        fi
        LAST_LABEL="$("$candidate" --version 2>&1 | head -n1)"
    fi
done

if [ -z "$PYTHON_EXE" ]; then
    if [ -n "${LAST_LABEL:-}" ]; then
        fail "Python 3.10+ required, found '$LAST_LABEL'. Install a newer Python (https://www.python.org/downloads/ or your package manager) and re-run."
    fi
    fail "Python 3.10+ not found. Install it (https://www.python.org/downloads/ or 'brew install python' / 'apt install python3') and re-run."
fi
step "Found Python: $PYTHON_LABEL"

# --- 2. Create or reuse the venv ----------------------------------------------
if [ -x "$VENV_DIR/bin/python" ]; then
    step "Reusing existing venv: $VENV_DIR"
else
    step "Creating venv at $VENV_DIR"
    "$PYTHON_EXE" -m venv "$VENV_DIR" || fail "Failed to create the venv at $VENV_DIR."
fi
VENV_PYTHON="$VENV_DIR/bin/python"
[ -x "$VENV_PYTHON" ] || fail "venv python missing at $VENV_PYTHON — delete $VENV_DIR and re-run."

step "Upgrading pip (quiet)"
"$VENV_PYTHON" -m pip install --upgrade pip --quiet --disable-pip-version-check \
    || fail "pip upgrade failed — check your network/proxy settings."

# --- 3. Install the harness ------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

if [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    step "Local checkout detected — installing editable from $SCRIPT_DIR"
    "$VENV_PYTHON" -m pip install -e "$SCRIPT_DIR" --disable-pip-version-check \
        || fail "Editable install failed — see the pip output above."
else
    step "Installing hunteros-harness from PyPI"
    if ! "$VENV_PYTHON" -m pip install hunteros-harness --disable-pip-version-check; then
        step "PyPI install failed — falling back to git ($REPO_URL)"
        "$VENV_PYTHON" -m pip install "git+$REPO_URL" --disable-pip-version-check \
            || fail "All install sources failed. Check the repo URL and your network, then re-run."
    fi
fi

"$VENV_PYTHON" -c "import hunter; print('hunteros-harness', hunter.__version__, 'installed')"

# --- 4. Next steps -----------------------------------------------------------------
echo
printf '\033[35mInstalled. Next steps:\033[0m\n'
echo
echo "  1. Activate the venv (or use the full path):"
echo "       source \"$VENV_DIR/bin/activate\""
echo "  2. Check the environment:"
echo "       hunter doctor"
echo "  3. Run the one-command demo (local practice target, deterministic scan):"
echo "       hunter demo"
echo "  4. Open the dashboard:"
echo "       hunter tui"
echo
echo "Scan only systems you own or are explicitly authorized to test."
