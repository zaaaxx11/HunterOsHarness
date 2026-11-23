"""CSS module — extracted from app.py for single-responsibility (Claude Code pattern).

This module owns the static STYLES string and resolved CSS builder.
Imported once by app.py — never recalculated, never inlined.
"""

from hunter.palette import SKINS, get_token

_CURRENT_SKIN = "teal"

STYLES = """Screen {
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
Header {
    background: $hunter-header_bg;
    color: $hunter-highlight;
    text-style: bold;
}
Header > .header--title {
    color: $hunter-highlight;
    text-style: bold;
}
Header > .header--clock {
    color: $hunter-dim;
}
Footer {
    background: $hunter-header_bg;
    color: $hunter-dim;
}
Footer > .footer--key {
    background: $hunter-bg;
    color: $hunter-highlight;
    text-style: bold;
}
Footer > .footer--description {
    color: $hunter-dim;
}
TabbedContent {
    background: $hunter-bg;
}
Tabs {
    background: $hunter-header_bg;
}
Tab {
    color: $hunter-dim;
    background: $hunter-header_bg;
    padding: 0 2;
}
Tab.-active {
    background: $hunter-bg;
    color: $hunter-highlight;
    text-style: bold;
    border-bottom: heavy $hunter-highlight;
}
Tab:hover {
    background: $hunter-panel_bg;
    color: $hunter-highlight_pale;
}
TabPane {
    background: $hunter-bg;
    padding: 1 2;
}
#tab-header {
    height: auto;
    dock: top;
    padding: 0 1;
    color: $hunter-dim;
    text-style: italic;
}
#logo {
    height: auto;
    padding: 0 0;
    color: $hunter-highlight_soft;
}
#wordmark {
    color: $hunter-highlight;
    padding: 0 0 1 0;
}
#home-menu {
    padding: 0 0;
    color: $hunter-highlight_pale;
}
#home-hint {
    padding: 1 0 0 0;
    color: $hunter-dim;
    text-style: italic;
}
.section-header {
    background: $hunter-panel_bg;
    color: $hunter-highlight;
    text-style: bold;
    padding: 0 1;
    margin: 0 0 1 0;
    border-left: thick $hunter-highlight;
}
.section-body {
    color: $hunter-highlight_pale;
    padding: 0 1;
}
#dashboard-empty, #findings-empty {
    display: none;
    height: 1fr;
    content-align: center middle;
    color: $hunter-dim;
    text-style: italic;
}
#runs-table {
    height: 1fr;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#findings-filter {
    height: 3;
    margin: 0 0 1 0;
    border: tall $hunter-panel_bg;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#findings-filter:focus {
    border: tall $hunter-highlight;
}
#findings-table {
    height: 1fr;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#finding-detail {
    height: 42%;
    border: tall $hunter-panel_bg;
    padding: 0 1;
    overflow-y: auto;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#events-log {
    height: 1fr;
    padding: 0 1;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#chat-input {
    border: tall $hunter-panel_bg;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#chat-input:focus {
    border: tall $hunter-highlight;
}
#chat-log {
    height: 1fr;
    padding: 0 1;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#status-bar {
    background: $hunter-header_bg;
    color: $hunter-highlight;
    padding: 0 1;
    height: 1;
}
#doctor-report {
    padding: 1 2;
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
#deploy-form {
    background: $hunter-bg;
}
.deploy-label {
    color: $hunter-dim;
}
#deploy-log {
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
Input {
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
Input:focus {
    border: tall $hunter-highlight;
}
Button {
    background: $hunter-panel_bg;
    color: $hunter-highlight_pale;
}
Button:hover {
    background: $hunter-deep;
    color: $hunter-bg;
}
Button.-primary {
    background: $hunter-highlight;
    color: $hunter-bg;
    text-style: bold;
}
DataTable > .datatable--header {
    background: $hunter-header_bg;
    color: $hunter-highlight;
    text-style: bold;
}
DataTable > .datatable--cursor {
    background: $hunter-deep;
    color: $hunter-bg;
}
DataTable > .datatable--hover {
    background: $hunter-panel_bg;
}
RichLog {
    background: $hunter-bg;
    color: $hunter-highlight_pale;
}
VerticalScroll {
    background: $hunter-bg;
}"""


def skin_css(skin: str = "teal") -> str:
    """Per-skin CSS vars via tokens (no hardcoded hex)."""
    _ = get_token("base", skin=skin)
    mapping = SKINS.get(skin, SKINS["teal"])
    return "\n".join(f"$hunter-{role}: {color};" for role, color in mapping.items()) + "\n"


def build_css(skin: str = "teal") -> str:
    """Full CSS: resolved skin vars + static rules."""
    return skin_css(skin) + STYLES


__all__ = ["STYLES", "build_css", "skin_css"]
