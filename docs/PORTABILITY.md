# Portability and support

This page is the support contract for the current HunterOS Harness release line. It
covers the core package and the documented installers. Optional dependencies have
their own upstream requirements; installing an extra does not expand the supported
platform policy below.

## Support matrix

| Environment | Status | Notes |
| --- | --- | --- |
| Windows x64 | Supported | Native installs use `install.ps1`. PowerShell 5.1, PowerShell 7, and `cmd.exe` are first-class shells. |
| macOS Intel (x86_64) | Supported | Use `install.sh` from bash or zsh. |
| macOS Apple Silicon (arm64) | Supported | Use `install.sh` from bash or zsh. Native ARM is preferred over running an x64 translation layer. |
| Linux x64 (x86_64) | Supported | Use `install.sh`. |
| Linux ARM64 (aarch64) | Supported | Use `install.sh`; availability of binary wheels for optional dependencies is governed by those projects. |
| WSL2 | Supported as Linux | Install inside the WSL2 distribution with the Linux instructions. WSL2 is not the same runtime as native Windows. |
| CPython 3.10, 3.11, 3.12, 3.13 | Supported | These are the supported Python versions. A virtual environment is required. |
| BSD, mobile, and embedded operating systems | Unsupported | These platforms are not release-gated or supported at this time. |

Windows ARM64, 32-bit operating systems, PyPy, and Python versions outside
3.10–3.13 are not first-class targets. They may work in some configurations, but
there is no portability or release guarantee for them.

### First-class shells

The command examples below are intentionally provided for bash, zsh, fish,
PowerShell 5.1/7, and `cmd.exe`. The POSIX installer detects the shell it runs
from and writes its tagged PATH block to the matching file — `.bashrc` for
bash, `.zshrc` for zsh, and `~/.config/fish/config.fish` (`fish_add_path`) for
fish. PowerShell and `cmd.exe` use the Windows `.cmd` shims created by
`install.ps1`; the installer also persists the venv and shim directories into
the user `PATH` so `cmd.exe` resolves `hunter` after a new shell.

## Installation

### macOS, Linux, and WSL2

Run the POSIX installer from bash, zsh, or fish (the installer itself is executed
by bash):

```bash
curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
```

For a checkout, use the local script instead:

```bash
bash install.sh --skip-setup
```

The installer creates the dedicated venv at `~/.hunteros/venv`. To install
manually from a checkout without the installer:

```bash
python3 -m venv "$HOME/.hunteros/venv"
. "$HOME/.hunteros/venv/bin/activate"
python -m pip install -e .
```

The installer registers `~/.hunteros/bin` for bash, zsh, and fish automatically.
If the shims are not on `PATH` yet, add them by hand:

```fish
fish_add_path "$HOME/.hunteros/bin"
fish_add_path "$HOME/.hunteros/venv/bin"
```

Use `source ~/.hunteros/venv/bin/activate.fish` when working with a manually
created venv. `~` in WSL2 means the Linux distribution's home directory, not the
native Windows profile.

### Native Windows

PowerShell 5.1 and PowerShell 7 use the same installer:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
```

For a local checkout:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -SkipSetup
```

The installer creates `%USERPROFILE%\.hunteros\venv` and `.cmd` shims in
`%USERPROFILE%\.hunteros\bin`. Open a new shell after installation so the PATH
change is visible. If policy allows scripts for the current user, this is an
alternative to the per-command bypass:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

`cmd.exe` can use the same installed shims. A manual checkout installation from
`cmd.exe` is:

```bat
py -3.13 -m venv "%USERPROFILE%\.hunteros\venv"
"%USERPROFILE%\.hunteros\venv\Scripts\python.exe" -m pip install -e .
"%USERPROFILE%\.hunteros\venv\Scripts\python.exe" -m hunter --version
```

If the shims are not on PATH yet, invoke
`%USERPROFILE%\.hunteros\bin\hunter.cmd` directly or start a new `cmd.exe`.

## Environment variables by shell

The examples use a state directory outside the checkout. This is optional;
`hunter doctor` reports the active state location. Do not paste real secrets into
committed files or shell history. `hunter init` can store provider keys in the
user keys file instead.

### bash

```bash
export HUNTER_STATE_DIR="$HOME/.hunter-state"
export HUNTEROS_MODEL="gpt-4o"
export OPENAI_API_KEY="sk-..."       # example placeholder only
export HUNTEROS_NO_UPDATE_CHECK=1
hunter doctor
```

### zsh

```zsh
export HUNTER_STATE_DIR="$HOME/.hunter-state"
export HUNTEROS_MODEL="gpt-4o"
export OPENAI_API_KEY="sk-..."       # example placeholder only
export HUNTEROS_NO_UPDATE_CHECK=1
hunter doctor
```

### fish

```fish
set -x HUNTER_STATE_DIR "$HOME/.hunter-state"
set -x HUNTEROS_MODEL "gpt-4o"
set -x OPENAI_API_KEY "sk-..."       # example placeholder only
set -x HUNTEROS_NO_UPDATE_CHECK 1
hunter doctor
```

### PowerShell 5.1/7

```powershell
$env:HUNTER_STATE_DIR = Join-Path $HOME ".hunter-state"
$env:HUNTEROS_MODEL = "gpt-4o"
$env:OPENAI_API_KEY = "sk-..."       # example placeholder only
$env:HUNTEROS_NO_UPDATE_CHECK = "1"
hunter doctor
```

### `cmd.exe`

```bat
set "HUNTER_STATE_DIR=%USERPROFILE%\.hunter-state"
set "HUNTEROS_MODEL=gpt-4o"
set "OPENAI_API_KEY=sk-..."
set "HUNTEROS_NO_UPDATE_CHECK=1"
hunter doctor
```

The provider key variable can be changed to the provider in use, for example
`ANTHROPIC_API_KEY` or `OPENROUTER_API_KEY`. `HUNTEROS_CONFIG` can point to a
configuration file when a non-default config is needed. Environment variables
set with `export`, `set -x`, `$env:`, or `set` apply to the current shell unless
you deliberately make them persistent using that shell's own profile settings.

## Optional extras in the dedicated venv

Keep optional extras in the dedicated harness venv rather than installing them
into system Python. The installer-created venv is already dedicated; for a
manual install, create the venv first as in the installation section.

On macOS, Linux, or WSL2:

```bash
"$HOME/.hunteros/venv/bin/python" -m pip install \
  'hunteros-harness[browser,telegram,discord]'
# Browser support needs this separate, explicit download:
"$HOME/.hunteros/venv/bin/python" -m playwright install chromium
```

On PowerShell:

```powershell
$python = Join-Path $HOME ".hunteros\venv\Scripts\python.exe"
& $python -m pip install "hunteros-harness[browser,telegram,discord]"
# Browser support needs this separate, explicit download:
& $python -m playwright install chromium
```

On `cmd.exe`:

```bat
"%USERPROFILE%\.hunteros\venv\Scripts\python.exe" -m pip install "hunteros-harness[browser,telegram,discord]"
"%USERPROFILE%\.hunteros\venv\Scripts\python.exe" -m playwright install chromium
```

Use only the extras needed for the operator's deployment. LiteLLM is part of the
core install; the `llm` extra is retained as a compatibility alias. Browser
automation is optional, hunt-only, and scope-gated. HunterOS never downloads
Chromium automatically. Telegram and Discord also require their respective
provider tokens and allowlists; they are not needed for local deterministic use.

## WSL2 is a separate environment

WSL2 runs a Linux userspace with its own Python, venvs, PATH, home directory, and
state. Treat it as Linux:

- Run `install.sh` inside the WSL2 distribution and keep its venv under the Linux
  home directory. Do not reuse a Windows `.venv` or the native Windows
  `install.ps1` venv from WSL2.
- A native Windows installation and a WSL2 installation may both exist, but their
  `hunter` commands and `HUNTER_STATE_DIR` locations are independent. Confirm
  which one is active before operating on a ledger.
- Prefer storing the venv and active state under `/home/<user>` rather than a
  mounted `/mnt/c` path. This avoids common permission and filesystem-watch
  surprises; a mounted path is not otherwise a supported-runtime requirement.
- WSL2 networking and Windows firewall/proxy behavior can differ from native
  Linux. Test a provider endpoint only when needed, and use `hunter doctor`
  first.

Check the distinction with:

```bash
uname -a
python3 -c 'import platform, sys; print(sys.executable); print(platform.machine())'
wsl.exe --status       # run this from WSL2 when the Windows wsl.exe bridge is available
```

## Diagnostics and troubleshooting

Start with a version, interpreter, architecture, and package check:

```bash
hunter --version
python -c 'import platform, sys; print(sys.executable); print(sys.version); print(platform.machine())'
python -m pip --version
python -m pip check
hunter doctor
hunter doctor --json
```

Use the command appropriate to the current shell when checking PATH resolution:

| Shell | Check |
| --- | --- |
| bash/zsh/fish | `command -v hunter` |
| PowerShell | `Get-Command hunter` |
| `cmd.exe` | `where hunter` |

Common fixes:

- **Command not found or an old version runs:** open a new shell after the
  installer changes PATH. Compare the command location with the venv location;
  invoke the venv entry point directly to isolate PATH issues.
- **PowerShell says scripts are disabled:** use the documented
  `-ExecutionPolicy Bypass` command, or set `RemoteSigned` for the current user.
  This does not change `cmd.exe` behavior.
- **`python` selects the wrong interpreter:** use `python3` on POSIX, `py -3.13`
  on Windows, or the dedicated venv's absolute `python` path. Recreate the venv
  if it was made by an unsupported Python version.
- **Optional extra or browser action is unavailable:** install the extra into the
  active dedicated venv, then install Chromium separately for browser use. The
  runtime intentionally does not perform either installation.
- **`pip install` fails behind a proxy:** configure `HTTPS_PROXY` and
  `HTTP_PROXY` in the active shell before installing. Do not put proxy
  credentials in this repository.
- **State or ledger appears in the wrong place:** print `HUNTER_STATE_DIR`, check
  `hunter doctor`, and remember that WSL2 and native Windows have separate homes.
  Set an explicit state directory before retrying an operation.
- **The demo reports a busy port:** it normally chooses an ephemeral loopback
  port. Check for a leftover process (`lsof -i :<port>` on macOS/Linux/WSL2 or
  `netstat -ano | findstr :<port>` on Windows) and retry with a clean state
  directory if needed.
- **An ARM install fails while the core package is available:** the core package
  is Python-based, but a dependency may not publish a wheel for that architecture
  yet. Read the failing dependency's error, use a supported CPython version, and
  do not assume an x64 wheel is safe to force onto ARM.

For a clean installer retry, remove only the dedicated venv after preserving any
state you need, then rerun the installer. Do not delete a ledger just to fix a
PATH or dependency issue.

## Release gate and CI policy

A release is portability-ready only when the following checks are green or have
a documented runner limitation:

1. The source tree builds both an sdist and a wheel from `pyproject.toml`.
2. `twine check` accepts the built distributions.
3. A clean dedicated venv installs the built wheel, imports `hunter`, reports the
   expected version, runs `python -m hunter --version`, and passes `python -m pip
   check`.
4. CI exercises Python 3.10–3.13 on the primary x64 Linux and Windows jobs, and
   includes smoke coverage for macOS Intel, macOS Apple Silicon, and Linux ARM64.
5. Ruff checks source (and any tests only when they are present). Pytest is
   conditional: the public repository may intentionally omit untracked `tests/`,
   so CI skips that step rather than requiring unavailable tests or claiming test
   coverage that did not run.
6. No release-gate job requires provider secrets, a live external target, a live
   gateway, or a Chromium download. Optional extras are validated separately when
   their upstream runners and artifacts are available.

GitHub-hosted ARM labels can change availability. The current workflow uses
`ubuntu-24.04-arm` for Linux ARM64 and `macos-14` for Apple Silicon, while
`macos-15-intel` covers Intel. Linux ARM is a public-preview runner in many
organizations; an unavailable ARM label may require an organization-level runner
or a temporary non-blocking job. That infrastructure limitation does not change
the product support policy. The x64 jobs remain the baseline required checks.
