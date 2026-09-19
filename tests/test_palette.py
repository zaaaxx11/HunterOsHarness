"""M9-C shared palette and surface-wiring tests.

Palette tests keep terminal styling deterministic while asserting machine/chat
surfaces remain plain. Imports happen inside tests so a missing M9 module is a
red implementation failure rather than a collection mistake.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PALETTE = {
    "base": "#00FFE5",
    "highlight": "#4DFFF0",
    "highlight_soft": "#80FFF6",
    "highlight_pale": "#B3FFFC",
    "highlight_faint": "#E6FFFE",
    "deep": "#00B59E",
    "dim": "#007A70",
}
EXPECTED_ANSI = {
    "base": "\x1b[96m",
    "highlight": "\x1b[96m",
    "highlight_soft": "\x1b[96m",
    "highlight_pale": "\x1b[97m",
    "highlight_faint": "\x1b[97m",
    "deep": "\x1b[36m",
    "dim": "\x1b[2;36m",
}


def test_palette_hex_contract():
    from hunter.palette import PALETTE

    assert PALETTE == EXPECTED_PALETTE

    def brightness(hex_color: str) -> int:
        return sum(int(hex_color[index : index + 2], 16) for index in (1, 3, 5))

    ladder = ["base", "highlight", "highlight_soft", "highlight_pale", "highlight_faint"]
    assert [brightness(PALETTE[role]) for role in ladder] == sorted(
        brightness(PALETTE[role]) for role in ladder
    )


def test_palette_roles_are_distinct_and_theme_names_are_stable():
    from hunter.palette import PALETTE, make_theme

    highlights = ("highlight", "highlight_soft", "highlight_pale", "highlight_faint")
    assert len({PALETTE[role] for role in highlights}) == 4
    theme = make_theme()
    styles = getattr(theme, "styles", {})
    for role in EXPECTED_PALETTE:
        assert f"hunter.{role}" in styles


def test_ansi_fallback_contract():
    from hunter.palette import ANSI_FALLBACK, ANSI_RESET, palette_style

    assert ANSI_FALLBACK == EXPECTED_ANSI
    assert ANSI_RESET == "\x1b[0m"
    for role, prefix in EXPECTED_ANSI.items():
        assert palette_style(role, ansi=True) == prefix


def test_colorize_is_plain_when_ansi_disabled():
    from hunter.palette import colorize

    text = colorize("hello", "base", ansi=False)
    assert text == "hello"
    assert "\x1b[" not in text


def test_colorize_wraps_explicit_ansi_once():
    from hunter.palette import ANSI_FALLBACK, ANSI_RESET, colorize

    text = colorize("hello", "highlight", ansi=True)
    assert text == f"{ANSI_FALLBACK['highlight']}hello{ANSI_RESET}"
    assert text.count(ANSI_FALLBACK["highlight"]) == 1
    assert text.count(ANSI_RESET) == 1


def test_make_console_uses_shared_theme():
    from hunter.palette import make_console

    stdout_console = make_console()
    stderr_console = make_console(stderr=True)
    assert stdout_console.theme is not None
    assert stderr_console.theme is not None
    assert "hunter.base" in stdout_console.theme.styles
    assert "hunter.highlight" in stderr_console.theme.styles


def test_cli_repl_tui_daemon_use_palette_seams():
    paths = {
        ROOT / "src" / "hunter" / "cli" / "main.py",
        ROOT / "src" / "hunter" / "cli" / "daemon.py",
        ROOT / "src" / "hunter" / "chat" / "repl.py",
        ROOT / "src" / "hunter" / "tui" / "app.py",
    }
    raw_style_names = {"tokyo-night", 'style="cyan"', 'border_style="cyan"', "[green]", "[red]"}
    for path in paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "hunter.palette"
            for alias in node.names
        }
        assert imported & {"PALETTE", "make_console"}, path
        assert not any(style_name in source for style_name in raw_style_names), path


def test_plain_gateway_and_json_outputs_have_no_ansi(monkeypatch, tmp_path):
    from hunter.chat.commands import CommandContext, safe_execute
    from hunter.chat.sessions import ChatStore
    from hunter.cli.main import app
    from hunter.palette import colorize
    from hunter.llm.config import default_config
    from typer.testing import CliRunner

    store = ChatStore(tmp_path / "chat.db")
    try:
        context = CommandContext(
            store=store,
            config=default_config(),
            args="",
            options={"state_dir": str(tmp_path)},
        )
        reply = safe_execute("hunt", context)
    finally:
        store.close()

    assert "\x1b[" not in reply.text
    assert "\x1b[" not in colorize(reply.text, ansi=False)
    result = CliRunner().invoke(app, ["hunt", "status", "--state", str(tmp_path), "--json"])
    assert "\x1b[" not in result.stdout
