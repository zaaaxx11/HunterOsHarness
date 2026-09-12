"""HunterOs branding — chat banner text.

Single source for the words shown on the chat surface. Plain strings only:
rendering (rich panels, plain text, gateway captions) belongs to the
surfaces, so every consumer can restyle without touching doctrine.
"""

BANNER_TITLE = "HUNTEROS"
BANNER_TAGLINE = "Evidence or Nothing"
NO_FABRICATION_LINE = (
    "No fabricated claims: a finding exists only when the hash-chained "
    "ledger can replay its evidence."
)
HINT_LINE = "Type /help for commands — free text talks to the model."

# --- bare-`hunter` welcome panel (CLI surface) ------------------------------

WELCOME_TITLE = "HunterOs Harness"
WELCOME_SUBTITLE = "evidence-first security auditing"
WELCOME_LEDGER_LINE = "every finding is proven by a hash-chained ledger, or it does not exist"
WELCOME_NEXT_STEPS = (
    "hunter init    — configure a brain (LLM provider, key, model) in one wizard",
    "hunter demo    — first blood on a local practice target, no keys needed",
    "hunter doctor  — verify the environment end to end",
)
WELCOME_FOOTER = "help: hunter --help · scan only what you own"


def welcome_lines(version: str) -> list[str]:
    """The bare-`hunter` welcome body (rendered by the CLI as a rich panel)."""
    return [
        f"{WELCOME_TITLE} v{version} — {WELCOME_SUBTITLE}",
        "",
        WELCOME_LEDGER_LINE,
        "",
        "next steps:",
        *(f"  {line}" for line in WELCOME_NEXT_STEPS),
        "",
        WELCOME_FOOTER,
    ]


def banner_lines(
    *,
    version: str,
    tier: str = "basic",
    model: str = "",
    session_id: str = "",
) -> list[str]:
    """The banner body lines, ready for rich panels or plain printing.

    ``model`` may be empty (nothing configured) — the line then reads
    "(unset)" so the user knows to configure a brain rather than guessing.
    """
    return [
        f"{BANNER_TITLE} — {BANNER_TAGLINE}",
        f"v{version}  |  tier: {tier}  |  model: {model or '(unset)'}",
        f"session: {session_id or '(new)'}",
        NO_FABRICATION_LINE,
        HINT_LINE,
    ]
