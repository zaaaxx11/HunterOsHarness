"""VPS Deploy helpers for the TUI — SSH, SCP, install.sh orchestration.

All async. Used by :class:`hunter.tui.app.HunterTui` deploy tab.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

from rich.text import Text
from textual.widgets import RichLog

__all__ = ["DeployWorker", "deploy_ping_sync"]


class DeployWorker:
    """Async deploy pipeline: ping → upload install.sh → install → config → daemon."""

    def __init__(self, form: dict[str, str]) -> None:
        self._form = form
        self._host = form["host"]
        self._user = form["user"]
        self._port = form["port"]
        self._remote = form["remote"]
        self._use_key = form["use_key"] == "True"
        self._key_path = form["key"]
        self._password = form.get("pass", "")

    # -- SSH / SCP base commands ------------------------------------------------

    def _ssh_base(self) -> list[str]:
        opts = [
            "ssh", "-p", self._port,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
        ]
        if self._use_key:
            opts += ["-i", self._key_path]
        return opts

    def _scp_base(self) -> list[str]:
        if self._use_key:
            return [
                "scp", "-P", self._port,
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10",
                "-i", self._key_path,
            ]
        return [
            "sshpass", "-p", self._password,
            "scp", "-P", self._port,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
        ]

    def _full_ssh(self) -> list[str]:
        base = self._ssh_base()
        if not self._use_key:
            base = ["sshpass", "-p", self._password, *base]
        return [*base, f"{self._user}@{self._host}"]

    def _full_scp(self) -> list[str]:
        return self._scp_base()

    # -- steps ------------------------------------------------------------------

    async def _exec(self, cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        return proc.returncode or 0, out, err

    async def run(self, log: RichLog) -> None:
        """Full deploy pipeline. Raises RuntimeError on fatal failures."""
        if not self._use_key and not shutil.which("sshpass"):
            raise RuntimeError("sshpass not found — install it or use SSH key auth")
        if self._use_key and not Path(self._key_path).is_file():
            raise RuntimeError(f"SSH key not found: {self._key_path}")

        # 1 — ping
        log.write(Text("| Ping…", style="dim"))
        code, out, err = await self._exec([*self._full_ssh(), "echo", "pong"], timeout=15)
        if code != 0:
            raise RuntimeError(f"SSH ping failed: {err.strip()}")
        log.write(Text(f"| {out.strip()} — connected", style="dim green"))

        # 2 — upload install.sh
        log.write(Text("| Uploading install.sh…", style="dim"))
        src_install = _find_install_script()
        if not src_install:
            log.write(Text("| install.sh not found locally — skipping upload", style="yellow"))
        else:
            code, _, err = await self._exec(
                [*self._full_scp(), str(src_install), f"{self._user}@{self._host}:~/"],
                timeout=30,
            )
            if code != 0:
                raise RuntimeError(f"SCP upload failed: {err.strip()}")
            log.write(Text("| install.sh uploaded", style="dim green"))

        # 3 — run install.sh
        log.write(Text("| Installing HunterOs on VPS (may take a minute)…", style="dim"))
        code, out, _ = await self._exec(
            [*self._full_ssh(), "cd ~ && bash install.sh --skip-setup 2>&1"],
            timeout=180,
        )
        for line in out.splitlines()[:80]:
            log.write(Text(f"  | {line}", style="dim"))
        if code != 0:
            log.write(Text(f"Install exited code {code} — check output", style="bold yellow"))
        else:
            log.write(Text("| HunterOs installed", style="green"))

        # 4 — upload config + keys
        from hunter.runtime_paths import RuntimePaths

        paths = RuntimePaths.resolve(migrate=False)
        for fn, label in [(paths.config, "config.yaml"), (paths.keys, "keys.env")]:
            if fn.is_file():
                log.write(Text(f"| Uploading {label}…", style="dim"))
                code, _, err = await self._exec(
                    [*self._full_scp(), str(fn), f"{self._user}@{self._host}:{self._remote}/{fn.name}"],
                    timeout=15,
                )
                if code == 0:
                    log.write(Text(f"| {label} uploaded", style="dim green"))
                else:
                    log.write(Text(f"| {label} upload failed: {err.strip()}", style="yellow"))

        # 5 — start daemon
        log.write(Text("| Starting hunt daemon…", style="dim"))
        code, out, _ = await self._exec(
            [*self._full_ssh(),
             "export PATH=$HOME/.hunteros/bin:$PATH && hunt daemon start 2>&1"],
            timeout=15,
        )
        log.write(Text(f"| daemon: {out.strip() or 'started'}", style="dim green"))

        # Done
        log.write(Text(f"\nDeploy complete — {self._user}@{self._host}", style="bold green"))
        log.write(Text(f"   Remote: {self._remote}", style="dim"))
        ssh_cmd = f"ssh {'-i ' + self._key_path if self._use_key else ''}{self._user}@{self._host} -p {self._port}"
        log.write(Text(f"   SSH:  {ssh_cmd}", style="dim"))


def _find_install_script() -> Path | None:
    """Find install.sh relative to the package, or the repo root."""
    import hunter

    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "install.sh",
        Path(hunter.__file__).resolve().parent.parent.parent / "install.sh",
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def deploy_ping_sync(form: dict[str, str]) -> tuple[bool, str]:
    """Synchronous ping for the non-blocking Ping button. Returns (ok, message)."""
    host, user, port = form["host"], form["user"], form["port"]
    use_key = form["use_key"] == "True"

    if use_key:
        cmd = [
            "ssh", "-i", form["key"], "-p", port,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}", "echo pong",
        ]
    else:
        cmd = [
            "sshpass", "-p", form.get("pass", ""),
            "ssh", "-p", port,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}", "echo pong",
        ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, f"pong — {host} reachable"
        return False, f"pong failed: {result.stderr.strip()}"
    except Exception as exc:
        return False, f"pong error: {exc}"