"""HunterError taxonomy — one error language for CLI, TUI, chat, and gateway.

Rendering rules (ported from the reference error UX, tightened by our doctrine):
- ``[BLOCKED]``  — scope-gate / claim-gate / approval refusals: name the rule,
  never suggest a "fix" that would widen scope. Always ledgered upstream.
- ``[ERROR <layer>]`` — everything else: 2 lines max (what happened, what to
  do). ``detail`` is for log/verbose only and must never contain secrets.
- ``[RETRYING n/m]`` — visible retries, not silence (produced by the router,
  not this module).

Exit-code map (stable contract for scripts):
    0 ok · 1 generic · 2 usage · 3 scope denied · 4 auth/billing ·
    5 rate limit · 6 claim-gate violation · 7 ledger integrity ·
    8 config · 130 interrupted
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_SCOPE_DENIED = 3
EXIT_AUTH = 4
EXIT_RATE_LIMIT = 5
EXIT_CLAIM_GATE = 6
EXIT_LEDGER = 7
EXIT_CONFIG = 8
EXIT_INTERRUPT = 130

LAYERS = (
    "provider", "endpoint", "auth", "billing", "scope", "ledger",
    "engine", "tool", "config", "approval", "disk", "usage",
)

_LAYER_EXIT: dict[str, int] = {
    "scope": EXIT_SCOPE_DENIED,
    "auth": EXIT_AUTH,
    "billing": EXIT_AUTH,
    "rate_limit": EXIT_RATE_LIMIT,
    "claim": EXIT_CLAIM_GATE,
    "ledger": EXIT_LEDGER,
    "config": EXIT_CONFIG,
    "usage": EXIT_USAGE,
}

_BLOCKED_LAYERS = frozenset({"scope", "claim", "approval"})


class HunterError(Exception):
    """A classified, user-actionable error. Every failure should become one."""

    def __init__(
        self,
        code: str,
        layer: str,
        message: str,
        *,
        hint: str = "",
        detail: str = "",
        retryable: bool = False,
        exit_code: int | None = None,
    ) -> None:
        if layer not in LAYERS:
            layer = "engine"
        self.code = code
        self.layer = layer
        self.message = message
        self.hint = hint
        self.detail = detail
        self.retryable = retryable
        self.exit_code = exit_code if exit_code is not None else _LAYER_EXIT.get(layer, EXIT_ERROR)
        super().__init__(message)

    @property
    def blocked(self) -> bool:
        return self.layer in _BLOCKED_LAYERS

    def user_message(self) -> str:
        prefix = "[BLOCKED]" if self.blocked else f"[ERROR {self.layer}]"
        lines = [f"{prefix} {self.message}"]
        if self.hint:
            lines.append(f"Hint: {self.hint}")
        return "\n".join(lines[:2])

    def __str__(self) -> str:  # keep logs identical to user view minus detail
        return self.user_message()


def build_error_surface(exc: BaseException) -> dict:
    """Structured descriptor for TUI/gateway rendering.

    MUST NEVER RAISE — surfacing diagnostics may not break the error path
    they describe (reference invariant, ported verbatim).
    """
    try:
        if isinstance(exc, HunterError):
            return {
                "layer": exc.layer,
                "code": exc.code,
                "retryable": exc.retryable,
                "hint": exc.hint,
                "message": exc.message,
                "exit_code": exc.exit_code,
                "blocked": exc.blocked,
            }
        return {
            "layer": "engine",
            "code": f"unexpected.{type(exc).__name__}",
            "retryable": False,
            "hint": "re-run with --verbose for details",
            "message": str(exc)[:300],
            "exit_code": EXIT_ERROR,
            "blocked": False,
        }
    except Exception:  # pragma: no cover — last resort, still never raises
        return {
            "layer": "engine", "code": "unexpected.unknown", "retryable": False,
            "hint": "", "message": "unrenderable error", "exit_code": EXIT_ERROR,
            "blocked": False,
        }
