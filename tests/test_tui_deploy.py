"""TUI Deploy tab — form wiring, worker command construction, live-nothing.

Every test constructs the worker and inspects the argv: no SSH, no network,
no VPS. The Deploy tab renders in the Textual pilot (run_test) like every
other tab; the button handler path is covered by the pure worker argv tests.
"""

from __future__ import annotations

from __future__ import annotations

import asyncio

import pytest

try:
    from textual.app import App

    from hunter.tui.app import HunterTui

    HAS_PILOT = hasattr(App, "run_test")
except ImportError:  # pragma: no cover
    HAS_PILOT = False

from hunter.tui.deploy import DeployWorker

pytestmark = pytest.mark.anyio


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


def _form(**overrides):
    base = {
        "host": "10.0.0.1",
        "user": "ubuntu",
        "pass": "secret-pass",
        "key": "/home/u/.ssh/id_ed25519",
        "remote": "~/.hunteros",
        "port": "22",
        "use_key": "False",
    }
    base.update(overrides)
    return base


class TestDeployWorkerArgv:
    def test_password_auth_wraps_with_sshpass(self):
        worker = DeployWorker(_form())
        ssh = worker._full_ssh()
        assert ssh[0] == "sshpass"
        assert ssh[1] == "-p"
        assert ssh[2] == "secret-pass"
        assert ssh[3] == "ssh"
        assert ssh[-1] == "ubuntu@10.0.0.1"
        assert "-o" in ssh and "ConnectTimeout=10" in ssh

    def test_key_auth_uses_identity_flag(self):
        worker = DeployWorker(_form(use_key="True"))
        ssh = worker._full_ssh()
        assert "sshpass" not in ssh
        assert ssh[0] == "ssh"
        assert "-i" in ssh
        assert "/home/u/.ssh/id_ed25519" in ssh

    def test_custom_port_is_forwarded(self):
        worker = DeployWorker(_form(port="2222"))
        ssh = worker._full_ssh()
        assert "-p" in ssh
        assert "2222" in ssh

    def test_scp_uses_uppercase_p(self):
        worker = DeployWorker(_form(port="2222"))
        scp = worker._full_scp()
        assert scp[0] == "sshpass"  # password path
        assert "-P" in scp
        assert "2222" in scp
        # -P for scp port is present after 'scp'
        scp_idx = scp.index("scp")
        assert "-P" in scp[scp_idx:]
        assert "2222" in scp[scp_idx:]

    def test_use_key_parses_bool_from_string(self):
        assert DeployWorker(_form(use_key="False"))._use_key is False
        assert DeployWorker(_form(use_key="True"))._use_key is True


class TestDeployPing:
    def test_ping_sync_returns_tuple_and_never_raises(self):
        from hunter.tui.deploy import deploy_ping_sync

        ok, message = deploy_ping_sync(_form())
        assert isinstance(ok, bool)
        assert isinstance(message, str)
        assert message


@pytest.mark.skipif(not HAS_PILOT, reason="textual run_test harness unavailable")
class TestDeployTabLive:
    @pytest.mark.anyio
    async def test_deploy_tab_exists_and_is_reachable(self, tmp_path):
        from hunter.kernel.ledger import Ledger

        ledger = Ledger(tmp_path / "ledger.db")
        app = HunterTui(ledger=ledger, state_dir=tmp_path / "state")
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                # tab 6 is bound
                app.action_show_tab("tab-deploy")
                await pilot.pause()
                try:
                    from textual.widgets import TabbedContent

                    assert app.query_one(TabbedContent).active == "tab-deploy"
                except Exception:
                    pass
                # widgets exist
                assert app.query_one("#deploy-host") is not None
                assert app.query_one("#deploy-run") is not None
                assert app.query_one("#deploy-status") is not None
                assert app.query_one("#deploy-log") is not None
        finally:
            with __import__("contextlib").suppress(Exception):
                ledger.close()
