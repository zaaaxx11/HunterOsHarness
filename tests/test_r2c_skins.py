"""R2-C skins-as-data (TDD RED — EXPECTED-FAIL-R2C).

Prod targets (READ ONLY, do NOT edit):
- hunter.palette.SKINS (NEW) + get_token/get_skin_token + skin_css/make_theme(skin)
- hunter.branding single-source re-export (no copied map)
- hunter.tui.app.set_skin / skin_css / theme hot-reload (NEW)
- per-fn -> prod:
  registry teal verbatim + midnight/amber -> hunter.palette.SKINS
  get_token consumers -> hunter.palette.get_token + tui builders
  style builders -> hunter.palette.skin_style / rich_style via token
  skin_css/theme hot-reload -> hunter.palette.skin_css + make_theme(skin=..)
  set_skin unknown HunterError + persist ui.skin -> hunter.tui.app.set_skin
  no-hex gate -> tui/app.py + cli surfaces (no hardcoded #RRGGBB)
  copy single-sourced -> hunter.branding.SKINS is hunter.palette.SKINS

TDD red: EXPECTED-FAIL-R2C until skins-as-data lands.
No TUI loop/sockets/sleep. ANSI stripped before text asserts.
Adversarial: rstrip comparator; teal pinned verbatim #00FFE5.
"""
from __future__ import annotations

import re

import pytest

R2C = "EXPECTED-FAIL-R2C:skins-as-data (R2-C skins)"
TEAL = "#00FFE5"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
HEX_RE = re.compile(r"#[0-9A-Fa-f]{6}\b")


def _strip(text: str) -> str:
    return ANSI_RE.sub("", str(text or "")).rstrip("\n").rstrip()


def _require_skins():
    import hunter.palette as palette

    skins = getattr(palette, "SKINS", None)
    if skins is None:
        pytest.fail(f"{R2C} — hunter.palette.SKINS registry missing")
    return palette, skins


def test_r2c_skins_registry_teal_verbatim_midnight_amber():
    """Registry pins teal verbatim plus midnight + amber skins."""
    _, skins = _require_skins()
    assert skins.get("teal", {}).get("base") == TEAL, "teal base verbatim #00FFE5"
    assert "midnight" in skins and "amber" in skins, "midnight + amber skins required"
    for name, mapping in skins.items():
        assert "base" in mapping, f"skin {name} needs a base token"


def test_r2c_skins_get_token_consumers():
    """get_token is the consumer seam; builders resolve through it."""
    palette, skins = _require_skins()
    get_token = getattr(palette, "get_token", None) or getattr(palette, "get_skin_token", None)
    if get_token is None:
        pytest.fail(f"{R2C} — hunter.palette.get_token/get_skin_token missing")
    assert get_token("base") == TEAL or get_token("base", skin="teal") == TEAL
    assert get_token("base", skin="midnight") != get_token("base", skin="amber")


def test_r2c_skins_style_builders_use_tokens():
    """Style builders go through tokens (no hardcoded hex at call sites)."""
    palette, _ = _require_skins()
    builder = getattr(palette, "skin_style", None) or getattr(palette, "rich_style", None)
    if builder is None:
        pytest.fail(f"{R2C} — hunter.palette.skin_style/rich_style missing")
    style = builder("base")
    assert style is not None


def test_r2c_skins_css_theme_hot_reload():
    """skin_css + make_theme(skin=..) hot-reload without restart."""
    palette, _ = _require_skins()
    skin_css = getattr(palette, "skin_css", None)
    make_theme = getattr(palette, "make_theme", None)
    if skin_css is None or make_theme is None:
        pytest.fail(f"{R2C} — hunter.palette.skin_css/make_theme missing")
    first = _strip(skin_css("teal"))
    second = _strip(skin_css("midnight"))
    assert first != second, "per-skin css must differ (hot-reload seam)"
    assert make_theme(skin="teal") is not None and make_theme(skin="amber") is not None


def test_r2c_skins_set_skin_unknown_huntererror_persist(tmp_path, monkeypatch):
    """set_skin unknown -> HunterError; known persists ui.skin via write_config."""
    import hunter.tui.app as tui_app

    set_skin = getattr(tui_app, "set_skin", None)
    if set_skin is None:
        pytest.fail(f"{R2C} — hunter.tui.app.set_skin missing")
    from hunter.errors import HunterError

    with pytest.raises(HunterError):
        set_skin("no-such-skin-xyz")
    seen: dict = {}

    def _fake_write(updates, target=None, **kw):
        seen.update(updates)
        return str(target or "cfg")

    monkeypatch.setattr("hunter.llm.writing.write_config", _fake_write)
    set_skin("midnight")
    assert "ui" in seen and seen["ui"].get("skin") == "midnight", "must persist ui.skin"


def test_r2c_skins_no_hex_gate():
    """No hardcoded hex outside the single registry (skins-as-data gate)."""
    _require_skins()
    from pathlib import Path

    app_src = (Path(__file__).resolve().parents[1] / "src" / "hunter" / "tui" / "app.py").read_text(
        encoding="utf-8")
    hits = [ln for ln in app_src.splitlines() if HEX_RE.search(ln) and "test" not in ln.lower()]
    assert hits == [], f"{R2C} — hardcoded hex in tui/app.py: {hits[:3]}"


def test_r2c_skins_copy_single_sourced():
    """branding re-exports the palette registry (copy single-sourced)."""
    _require_skins()
    import hunter.branding as branding
    import hunter.palette as palette

    assert getattr(branding, "SKINS", None) is getattr(palette, "SKINS", None), (
        f"{R2C} — hunter.branding.SKINS must be hunter.palette.SKINS (single-sourced)"
    )
