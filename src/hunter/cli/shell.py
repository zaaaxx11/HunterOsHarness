"""Interactive HUNT shell — the `hunteros` entry point.

Wiring, top to bottom:

    banner  ->  REPL  ->  { plain chat | slash command }
                  |                |
                  |                +-> command registry (32 commands)
                  +-> HuntSession  ->  workflow.loop_v3  ->  verify (L1..L4)
                                          |                       |
                                          +-> state.json          +-> evidence/

Every collaborator is injected, so the shell stays a thin view and the
anti-fabrication gate lives below it (hunter.verify), not in the prompt.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

HINT = "Type /help for commands  \u00b7  /hunt <target> to start  \u00b7  /btw <q> for a side channel"

CHAT_SYSTEM = (
    "You are HUNT, an evidence-first security hunting assistant running inside a terminal. "
    "You help the operator scope targets, reason about vulnerability classes, and interpret "
    "findings that the harness already verified. You never claim a vulnerability is confirmed "
    "unless it carries anchored evidence (file:line or a request/response pair). "
    "Be concise and concrete. Answer in the operator's language."
)


# --------------------------------------------------------------------------- #
# LLM adapter: repo provider -> the loop's complete()/complete_with_tools() API
# --------------------------------------------------------------------------- #
class LLMAdapter:
    """Adapts hunter.llm providers to the loop_v3 interface."""

    def __init__(self, provider: Any, tier: str = "hunter") -> None:
        self.provider = provider
        self.tier = tier

    def _turn(self, system: str, user: str, tools: list | None = None,
              tool_choice: str | None = None):
        msgs = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        if tool_choice:
            try:
                return self.provider.complete(
                    self.tier, msgs, tools=tools, tool_choice=tool_choice
                )
            except TypeError:
                pass  # provider without the knob: fall back to the default
        return self.provider.complete(self.tier, msgs, tools=tools)

    def complete(self, system: str, user: str) -> str:
        turn = self._turn(system, user)
        return (
            getattr(turn, "text", "")
            or getattr(turn, "reasoning", "")
            or ""
        )

    def complete_with_tools(self, system: str, user: str, tools: list,
                            tool_choice: str | None = None) -> dict:
        turn = self._turn(system, user, tools=tools, tool_choice=tool_choice)
        calls: list[dict] = []
        for tc in (getattr(turn, "tool_calls", None) or []):
            args = getattr(tc, "arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            calls.append({"name": getattr(tc, "name", ""), "arguments": args or {}})
        return {
            "text": getattr(turn, "text", "") or "",
            "tool_calls": calls,
            "reasoning": getattr(turn, "reasoning", "") or "",
        }


def apply_model_tiers(cfg: Any, tiers: dict | None) -> list[str]:
    """Write tier->model overrides onto a loaded config; return what changed.

    The config carries ``model_tiers`` as {tier: block}, where a block is an
    object or a dict holding ``provider``/``model``/``timeout``. Setting only
    ``session.model_tiers`` used to change nothing at all, because the provider
    is built from the config — this is the bridge that makes /model real.
    """
    changed: list[str] = []
    blocks = getattr(cfg, "model_tiers", None)
    if blocks is None or not isinstance(blocks, dict) or not tiers:
        return changed
    for tier, model in dict(tiers).items():
        model = str(model or "").strip()
        if not model:
            continue
        block = blocks.get(tier)
        if isinstance(block, dict):
            if str(block.get("model") or "") != model:
                block["model"] = model
                changed.append(f"{tier}->{model}")
        elif block is not None:
            if str(getattr(block, "model", "") or "") != model:
                try:
                    setattr(block, "model", model)
                    changed.append(f"{tier}->{model}")
                except Exception:  # noqa: BLE001 - frozen block: skip, don't crash
                    pass
        else:
            blocks[tier] = {"provider": "devora", "model": model, "timeout": 300}
            changed.append(f"{tier}->{model}")
    return changed


def build_provider(model_tiers: dict | None = None) -> Any:
    """Build the repo provider. Returns None when no provider is configured."""
    try:
        from hunter.llm.config import load_config
        from hunter.llm.router import provider_from_config

        cfg = load_config()
        apply_model_tiers(cfg, model_tiers or {})
        return provider_from_config(cfg)
    except Exception as exc:  # noqa: BLE001 - the shell must survive a bad config
        print(f"[warn] no LLM provider: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Sane defaults for the provider quirks this project was built against:
    # reasoning models burn the default output budget on reasoning_content and
    # stop before the tool call, so the hunter needs real headroom.
    os.environ.setdefault("HUNTEROS_HUNTER_MODE", "auto")
    os.environ.setdefault("HUNTEROS_MAX_TOKENS", "16000")

    # import here so `--help`/selftest stay fast and dependency-light
    from hunter.cli.banner import animate_banner
    from hunter.cli.repl import run_repl
    from hunter.cli.commands import registry as cmdreg
    from hunter.cli.commands import core as _core  # noqa: F401 - registers commands
    from hunter.session import HuntSession
    import hunter.verify as verify_pkg

    print(animate_banner())
    print(HINT)
    print()

    # -- selftest seam ------------------------------------------------------
    if os.environ.get("HUNT_SELFTEST") or "--selftest" in argv:
        print("SELFTEST OK")
        return 0

    # -- session ------------------------------------------------------------
    session = HuntSession(name=Path.cwd().name or "hunt")
    if argv and not argv[0].startswith("-"):
        session.target = argv[0]

    provider = build_provider(session.model_tiers)
    llm = LLMAdapter(provider, tier="hunter") if provider is not None else None

    verify_hook = verify_pkg.verify_claim

    def engine(active: HuntSession) -> None:
        """Run the hunt loop against this session (called from a worker thread)."""
        from hunter.workflow.loop_v3 import HuntLoop

        if llm is None:
            active.log("[error] no LLM provider configured — cannot hunt")
            print("[error] no LLM provider configured", file=sys.stderr)
            return

        state_path = Path(
                os.path.expanduser(f"~/.hunter/sessions/{active.name}/hunt_state.json")
            )

        def _log(message: str) -> None:
            active.log(message)
            text_line = str(message)
            # Tool activity gets the Claude-Code row shape; other lines print
            # through the spinner so they never tear the live status line.
            if "tool call" in text_line.lower():
                tool_call("hunt", text_line.strip())
            else:
                spin.log(text_line)

        from hunter.cli.spinner import Spinner, tool_call

        spin = Spinner(label="Hunting")
        spin.start()
        loop = HuntLoop(
            llm=llm,
            verify_claim=verify_hook,
            target=active.target,
            goals=active.goals,
            wall_seconds=active.wall_seconds,
            idle_seconds=active.idle_seconds,
            budget_usd=active.budget,
            state_path=state_path,
            model_tiers=active.model_tiers,
            log=_log,
        )
        try:
            state = loop.run()
        finally:
            spin.stop()
        active.round = getattr(state, "round", active.round)
        active.findings = list(getattr(state, "findings", active.findings) or [])
        active.completion_reason = getattr(state, "completion_reason", None)

    def chat(text: str) -> None:
        if llm is None:
            print("(no LLM provider configured — chat unavailable)")
            return
        from hunter.cli.spinner import Spinner

        spin = Spinner()
        spin.start()
        try:
            answer = llm.complete(CHAT_SYSTEM, text)
        except Exception as exc:  # noqa: BLE001
            spin.stop()
            print(f"[error] {type(exc).__name__}: {exc}")
            # Self-repair: the LLM can fix its own harness. Feed the traceback
            # back to the model so a follow-up "fix it" prompt can patch the
            # broken file and the next turn succeeds.
            import traceback as _tb
            tb = _tb.format_exc()
            try:
                session.log(f"[crash] chat turn — {type(exc).__name__}: {exc}")
                session._last_crash = tb[-2000:]
            except Exception:  # noqa: BLE001
                pass
            return
        spin.stop()
        print(answer)

    session._engine = engine
    session._chat = chat

    # -- REPL ---------------------------------------------------------------
    def on_chat(text: str) -> None:
        session.log(f"user: {text[:200]}")
        chat(text)

    def on_command(line: str) -> bool:
        cmd = line.strip()
        if cmd in ("/exit", "/quit", "/q"):
            return False
        try:
            out = cmdreg.dispatch(line, session)
        except Exception as exc:  # noqa: BLE001 - a bad command must not kill the shell
            out = f"[error] {type(exc).__name__}: {exc}"
        if out:
            print(out)
        return True

    try:
        run_repl(on_chat=on_chat, on_command=on_command)
    except KeyboardInterrupt:
        print("\nsession closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())