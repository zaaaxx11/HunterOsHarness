#!/usr/bin/env bash
# install-toolchain.sh — the offensive binaries the eight toolchain tools wrap.
#
# toolchain.py registers forge_build, forge_test, cast_call, slither_run,
# port_scan, nuclei_scan, gobuster_dir and sqlmap_test. Each one shells out to
# a real binary and reports `_unavailable` when it is missing — which is the
# correct behaviour, but it means a fresh checkout has eight tools that all
# refuse. install.sh only installs the Python package; this installs the
# binaries it drives.
#
# Idempotent: anything already on PATH is skipped, so re-running is cheap.
# Each installer is independent — one failing does not block the others.
#
# Usage:
#   ./install-toolchain.sh              # install everything missing
#   ./install-toolchain.sh nuclei sqlmap  # only these
#   ./install-toolchain.sh --check      # report status, install nothing

set -uo pipefail

TOOLS=(forge cast slither nuclei sqlmap gobuster masscan)
ONLY=()
CHECK=0

for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) ONLY+=("$arg") ;;
  esac
done

if [ ${#ONLY[@]} -gt 0 ]; then
  TOOLS=("${ONLY[@]}")
fi

log()  { printf '%s\n' "$*"; }
ok()   { printf '  [ok] %s\n' "$*"; }
skip() { printf '  [--] %s\n' "$*"; }
miss() { printf '  [!!] %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"
case "$OS" in
  Linux)  PLAT=linux ;;
  Darwin) PLAT=macos ;;
  *) log "unsupported platform: $OS (this installer covers Linux and macOS)"; exit 1 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) log "unsupported architecture: $ARCH"; exit 1 ;;
esac

# ------------------------------------------------------------------ foundry

install_foundry() {
  # Check first, unconditionally: a host that already has forge and cast must
  # not be pushed into foundryup, which needs network and fails on a host
  # where the binaries came from somewhere else (a package manager, a tarball,
  # a different user's install).
  if have forge && have cast; then
    skip "foundry already present ($(forge --version 2>/dev/null | head -1))"
    return 0
  fi
  log "  installing foundry (forge, cast, anvil)..."
  if have foundryup; then
    foundryup && return 0
  fi
  curl -L https://foundry.paradigm.xyz 2>/dev/null | bash || return 1
  # foundryup lands in ~/.foundry/bin, which is not on a non-interactive PATH.
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup || return 1
}

# ------------------------------------------------------------------- slither

install_slither() {
  if have slither; then
    skip "slither already present ($(slither --version 2>/dev/null | head -1))"
    return 0
  fi
  log "  installing slither..."
  # solc-select is slither's compiler backend; without it slither finds no
  # compiler and every run fails with a confusing "solc not found".
  python3 -m pip install --user --quiet slither-analyzer solc-select 2>/dev/null \
    || pip3 install --user --quiet slither-analyzer solc-select 2>/dev/null \
    || return 1
  solc-select install latest >/dev/null 2>&1 || true
}

# -------------------------------------------------------------------- nuclei

install_nuclei() {
  if have nuclei; then
    skip "nuclei already present ($(nuclei --version 2>/dev/null | head -1))"
    return 0
  fi
  log "  installing nuclei..."
  local dest="$HOME/.local/bin"
  mkdir -p "$dest"
  local url="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${PLAT}_${GOARCH}.zip"
  local tmp; tmp="$(mktemp -d)"
  if curl -fsSL "$url" -o "$tmp/nuclei.zip" 2>/dev/null; then
    unzip -oq "$tmp/nuclei.zip" -d "$tmp" && mv "$tmp/nuclei" "$dest/nuclei" && chmod +x "$dest/nuclei"
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  # Fall back to Go when the release asset is unreachable.
  if have go; then
    GOFLAGS=-mod=mod go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && return 0
  fi
  return 1
}

# -------------------------------------------------------------------- sqlmap

install_sqlmap() {
  if have sqlmap; then
    skip "sqlmap already present ($(sqlmap --version 2>/dev/null | head -1))"
    return 0
  fi
  log "  installing sqlmap..."
  local dest="$HOME/.local/bin"
  mkdir -p "$dest"
  local tmp; tmp="$(mktemp -d)"
  if curl -fsSL https://github.com/sqlmapproject/sqlmap/tarball/master -o "$tmp/sqlmap.tar.gz" 2>/dev/null; then
    tar -xzf "$tmp/sqlmap.tar.gz" -C "$tmp"
    local dir; dir="$(find "$tmp" -maxdepth 1 -type d -name 'sqlmapproject-sqlmap-*' | head -1)"
    [ -n "$dir" ] && mv "$dir" "$dest/sqlmap" && chmod +x "$dest/sqlmap/sqlmap.py"
    ln -sf "$dest/sqlmap/sqlmap.py" "$dest/sqlmap.py" 2>/dev/null || true
    rm -rf "$tmp"
    have sqlmap && return 0
  fi
  rm -rf "$tmp"
  python3 -m pip install --user --quiet sqlmap 2>/dev/null && return 0
  return 1
}

# ------------------------------------------------------------------ gobuster

install_gobuster() {
  if have gobuster; then
    skip "gobuster already present"
    return 0
  fi
  log "  installing gobuster..."
  local dest="$HOME/.local/bin"
  mkdir -p "$dest"
  local tmp; tmp="$(mktemp -d)"
  local url="https://github.com/OJ/gobuster/releases/latest/download/gobuster_${PLAT}_${GOARCH}.zip"
  if curl -fsSL "$url" -o "$tmp/gobuster.zip" 2>/dev/null; then
    unzip -oq "$tmp/gobuster.zip" -d "$tmp" && mv "$tmp/gobuster" "$dest/gobuster" && chmod +x "$dest/gobuster"
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  if have go; then
    GOFLAGS=-mod=mod go install github.com/OJ/gobuster/v3@latest 2>/dev/null && return 0
  fi
  return 1
}

# ------------------------------------------------------------------- masscan

install_masscan() {
  if have masscan; then
    skip "masscan already present ($(masscan --version 2>/dev/null | head -1))"
    return 0
  fi
  log "  installing masscan (needs a compiler and libpcap-dev)..."
  local tmp; tmp="$(mktemp -d)"
  if curl -fsSL https://github.com/robertdavidgraham/masscan/tarball/master -o "$tmp/masscan.tar.gz" 2>/dev/null; then
    tar -xzf "$tmp/masscan.tar.gz" -C "$tmp"
    local dir; dir="$(find "$tmp" -maxdepth 1 -type d -name 'robertdavidgraham-masscan-*' | head -1)"
    if [ -n "$dir" ]; then
      (cd "$dir" && make -s >/dev/null 2>&1) && mv "$dir/bin/masscan" "$HOME/.local/bin/masscan" 2>/dev/null
    fi
    rm -rf "$tmp"
    have masscan && return 0
  fi
  rm -rf "$tmp"
  return 1
}

# ---------------------------------------------------------------------- main

log "toolchain installer — platform=$PLAT arch=$GOARCH"
log ""

if [ "$CHECK" -eq 1 ]; then
  for t in "${TOOLS[@]}"; do
    if have "$t"; then ok "$t"; else miss "$t (not installed)"; fi
  done
  exit 0
fi

FAILED=()
for tool in "${TOOLS[@]}"; do
  # forge and cast ship together in one foundry install, so both names map to
  # the same installer. Without this alias, `install_cast` is an unknown
  # command and the loop reports a failure for a tool that is already present.
  installer="install_$tool"
  if ! declare -f "$installer" >/dev/null 2>&1; then
    # forge, cast and anvil ship in one foundry install, so all three names
    # map to the same installer. Without this alias, `install_forge` and
    # `install_cast` are unknown commands and the loop reports failures for
    # tools that are already present.
    case "$tool" in
      forge|cast|anvil) installer=install_foundry ;;
    esac
  fi
  if ! declare -f "$installer" >/dev/null 2>&1; then
    miss "$tool has no installer in this script"
    FAILED+=("$tool")
    continue
  fi
  log "[$tool]"
  "$installer" || { miss "$tool failed — see the output above"; FAILED+=("$tool"); }
done

log ""
if [ ${#FAILED[@]} -eq 0 ]; then
  log "all requested tools are available."
else
  log "could not install: ${FAILED[*]}"
  log "the tools that did install work now; the rest report _unavailable until fixed."
fi

# The Go and release-asset installers put binaries in ~/.local/bin, which a
# non-interactive shell does not have on PATH. Say so rather than leaving the
# operator wondering why `nuclei` is still not found.
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) log ""
     log "note: ~/.local/bin is not on your PATH. Add it:"
     log "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

[ ${#FAILED[@]} -eq 0 ]
