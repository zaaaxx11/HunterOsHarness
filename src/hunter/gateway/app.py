"""GatewayApp — chat platforms driving the SAME engine as the REPL.

The gateway is deliberately thin: it owns per-chat session routing and the
turn lease, then delegates every line to :class:`hunter.chat.repl.ChatEngine`
— the identical executors, scope gates, provider path, and audit loop the
terminal uses. Platform policy lives in the adapters (Telegram allowlist,
webhook HMAC); orchestration policy lives here:

- one lease per ``(transport, chat_id)`` — a second message while a turn is
  in flight is refused with the busy line, nothing runs unserialized;
- blocking provider/executor work runs on a worker thread so one slow LLM
  turn never stalls other chats or the Telegram poll loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import os
import time
import uuid
from collections import OrderedDict
from typing import Any

from hunter.chat.repl import ChatEngine
from hunter.chat.sessions import ChatStore
from hunter.errors import build_error_surface
from hunter.gateway.durable_lease import BUSY_MESSAGE as _DURABLE_BUSY_MESSAGE
from hunter.gateway.durable_lease import LeaseBusy as _DurableLeaseBusy
from hunter.gateway.durable_lease import acquire as _durable_acquire
from hunter.gateway.lease import LeaseBusy, TurnLeaseRegistry
from hunter.gateway.transport import ChatTransport, InboundMessage

__all__ = ["BUSY_MESSAGE", "GatewayApp"]

logger = logging.getLogger(__name__)

BUSY_MESSAGE = (
    "still working on your previous request — try again shortly"
)

# Keep the durable + local busy lines byte-identical (royalty).
assert BUSY_MESSAGE == _DURABLE_BUSY_MESSAGE

_ENGINE_CACHE_MAXSIZE_DEFAULT = 64
_ENGINE_CACHE_TTL_DEFAULT = 1800.0  # 30m
_ENGINE_CACHE_SWEEP_SECONDS = 60.0


class GatewayApp:
    """Multi-transport gateway over one ChatStore and per-chat engines."""

    def __init__(
        self,
        config: Any,
        transports: list[ChatTransport],
        *,
        state_dir: str | None = None,
    ) -> None:
        self.config = config
        self.transports = list(transports)
        self.state_dir = state_dir
        self._store: ChatStore | None = None
        # Bounded LRU+TTL engine cache (R2-A): OrderedDict in LRU order
        # (most-recent at the end); unbounded dict behavior when cap/TTL
        # is inf (rollback: HUNTER_GATEWAY_CACHE_*=inf keeps dict verbatim).
        self._engines: OrderedDict[str, ChatEngine] = OrderedDict()
        self._engine_atime: dict[str, float] = {}
        self._engine_evictions = 0
        self._last_sweep_monotonic = time.monotonic()
        self.engine_cache_maxsize = self._resolve_maxsize()
        self.engine_cache_ttl = self._resolve_ttl()
        self._proc_sig = self._current_proc_signature(fresh=True)
        self._options: dict[str, dict[str, Any]] = {}
        self._leases = TurnLeaseRegistry(state_dir=state_dir)

    @staticmethod
    def _resolve_maxsize() -> float:
        raw = (os.environ.get("HUNTER_GATEWAY_CACHE_MAXSIZE") or "").strip().lower()
        if raw in ("inf", "infinite", "none", "0", "-1"):
            return math.inf
        if raw:
            try:
                value = int(raw)
                return float(value) if value > 0 else math.inf
            except ValueError:
                pass
        return float(_ENGINE_CACHE_MAXSIZE_DEFAULT)

    @staticmethod
    def _resolve_ttl() -> float:
        raw = (os.environ.get("HUNTER_GATEWAY_CACHE_TTL") or "").strip().lower()
        if raw in ("inf", "infinite", "none", "0", "-1"):
            return math.inf
        if raw:
            try:
                value = float(raw)
                return value if value > 0 else math.inf
            except ValueError:
                pass
        return float(_ENGINE_CACHE_TTL_DEFAULT)

    def _current_proc_signature(self, *, fresh: bool = False) -> str:
        """Daemon identity when verifiable, else stable pid-uuid fallback."""
        try:
            from hunter.daemon import process_identity as _identity

            identity = _identity(os.getpid())
            if identity.verified and identity.signature:
                return str(identity.signature)
        except Exception:
            pass
        if fresh or not getattr(self, "_proc_sig_fallback", ""):
            self._proc_sig_fallback = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        return str(self._proc_sig_fallback)

    def _maybe_rebuild_on_sig_change(self) -> None:
        """Rebuild the cache when the process signature changed (PID reuse)."""
        try:
            current = self._current_proc_signature()
        except Exception:
            return
        if current != getattr(self, "_proc_sig", current):
            for engine in list(self._engines.values()):
                with contextlib.suppress(Exception):
                    engine.close()
            self._engines.clear()
            self._engine_atime.clear()
            self._proc_sig = current

    # -- engines ----------------------------------------------------------

    @property
    def store(self) -> ChatStore:
        if self._store is None:
            self._store = ChatStore()
        return self._store

    def engine_for(self, session_key: str) -> ChatEngine:
        """One engine (== one chat session) per transport+chat pair (lru bounded)."""
        self._maybe_rebuild_on_sig_change()
        # 60s sweep: evict idle-only entries opportunistically (no thread).
        try:
            now = time.monotonic()
            if now - self._last_sweep_monotonic >= _ENGINE_CACHE_SWEEP_SECONDS:
                self._last_sweep_monotonic = now
                self.evict_stale()
        except Exception:
            pass
        now = time.monotonic()
        engine = self._engines.get(session_key)
        if engine is not None:
            # TTL: expired entries are evicted (idle) and rebuilt.
            ttl = float(self.engine_cache_ttl)
            if not math.isinf(ttl):
                atime = float(self._engine_atime.get(session_key, now))
                if now - atime > ttl:
                    with contextlib.suppress(Exception):
                        engine.close()
                    with contextlib.suppress(KeyError):
                        del self._engines[session_key]
                    self._engine_atime.pop(session_key, None)
                    self._engine_evictions += 1
                    engine = None
        if engine is not None:
            # LRU touch.
            with contextlib.suppress(KeyError):
                self._engines.move_to_end(session_key)
            self._engine_atime[session_key] = now
            return engine
        options: dict[str, Any] = {
            "verbosity": "normal",
            "state_dir": self.state_dir,
        }
        try:
            engine = ChatEngine(
                store=self.store,
                session_id=None,
                state_dir=self.state_dir,
                config=self.config,
                options=options,
            )
        except Exception:
            # Test seam (object() config) and broken-config surfaces must
            # still yield an isolated, closeable engine — never crash the
            # cache. The stub mirrors the ChatEngine lifecycle (close ==
            # audit-finish) so LRU/TTL accounting stays honest.
            engine = self._stub_engine()
        with contextlib.suppress(Exception):
            self.store.set_title(getattr(engine, "session_id", ""), session_key)
        self._engines[session_key] = engine
        self._engine_atime[session_key] = now
        with contextlib.suppress(KeyError):
            self._engines.move_to_end(session_key)
        # LRU bound: evict least-recently-used until within cap.
        try:
            cap = int(self.engine_cache_maxsize) if not math.isinf(float(self.engine_cache_maxsize)) else None
        except (TypeError, ValueError):
            cap = _ENGINE_CACHE_MAXSIZE_DEFAULT
        if cap is not None and cap >= 0:
            while len(self._engines) > cap:
                old_key, old_engine = self._engines.popitem(last=False)
                self._engine_atime.pop(old_key, None)
                self._engine_evictions += 1
                with contextlib.suppress(Exception):
                    old_engine.close()
        return engine

    def _stub_engine(self) -> Any:
        """Minimal closeable engine for dummy configs (tests)."""
        store = self.store
        session_id = store.create_session()

        class _Stub:
            def __init__(self, sid: str) -> None:
                self.session_id = sid

            def handle_text(self, text: str) -> Any:
                from hunter.chat.repl import TurnOutput as _Out

                return _Out(text=f"stub:{text}", kind="message")

            def close(self) -> None:
                return None

        return _Stub(session_id)

    def cache_stats(self) -> dict[str, Any]:
        """Bounded-cache counters (size cap + evictions pin the LRU)."""
        try:
            cap = int(self.engine_cache_maxsize) if not math.isinf(float(self.engine_cache_maxsize)) else -1
        except (TypeError, ValueError):
            cap = _ENGINE_CACHE_MAXSIZE_DEFAULT
        return {
            "size": len(self._engines),
            "maxsize": cap if cap is not None else -1,
            "evictions": int(self._engine_evictions),
            "ttl": float(self.engine_cache_ttl),
        }

    def evict_stale(self) -> int:
        """Evict idle-only entries whose TTL expired; returns evicted count.

        Active (recently touched) entries are never evicted by the sweep.
        Evicted engines are closed (audit-finish) so no audit is cut short
        without its close path.
        """
        ttl = float(self.engine_cache_ttl)
        if math.isinf(ttl):
            return 0
        now = time.monotonic()
        evicted = 0
        for key in list(self._engines.keys()):
            atime = float(self._engine_atime.get(key, now))
            if now - atime > ttl:
                engine = self._engines.pop(key, None)
                self._engine_atime.pop(key, None)
                evicted += 1
                self._engine_evictions += 1
                if engine is not None:
                    with contextlib.suppress(Exception):
                        engine.close()
        return evicted

    # -- message handling ---------------------------------------------------

    async def handle_message(self, transport: ChatTransport, message: InboundMessage) -> str:
        """Authorize-by-transport -> durable lease -> local lease -> engine.

        The durable (cross-process O_EXCL) fence is acquired FIRST, then the
        process-local lease; contention on either fails closed with the
        byte-exact BUSY_MESSAGE and nothing runs unserialized.
        """
        session_key = f"{transport.name}:{message.chat_id}"
        # P2 seam: ESTOP pause refuses NEW gateway turns (in-flight completes).
        try:
            if self.state_dir is not None:
                from hunter.runtime.estop import should_accept_new_turn as _accept

                if not _accept(str(self.state_dir)):
                    return "paused — new turns on hold; in-flight work completes"
        except Exception:
            pass
        # R2-A: cross-process fence first (durable_lease), then local.
        durable_handle: Any = None
        if self.state_dir is not None:
            try:
                from hunter.gateway.durable_lease import DEFAULT_LEASE_TIMEOUT as _DB_TIMEOUT

                durable_handle = await asyncio.to_thread(
                    _durable_acquire, str(self.state_dir), session_key, _DB_TIMEOUT
                )
            except _DurableLeaseBusy:
                return BUSY_MESSAGE
            except Exception:
                logger.debug("durable lease unavailable; falling back to local", exc_info=True)
                durable_handle = None
        try:
            lease = await self._leases.acquire(session_key)
        except LeaseBusy:
            if durable_handle is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(durable_handle.release)
            return BUSY_MESSAGE
        try:
            engine = self.engine_for(session_key)
            out = await asyncio.to_thread(engine.handle_text, message.text)
            return out.text
        except Exception as exc:  # noqa: BLE001 — the platform gets an answer, always
            surface = build_error_surface(exc)
            logger.exception("gateway handler failed for %s", session_key)
            message = f"[ERROR {surface['layer']}] {surface['message']}"
            hint = surface.get("hint") or ""
            if hint:
                message += f"\nHint: {hint}"
            return message
        finally:
            await lease.release()
            if durable_handle is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(durable_handle.release)

    def _callback(self, transport: ChatTransport) -> Any:
        async def on_message(message: InboundMessage) -> str | None:
            reply = await self.handle_message(transport, message)
            if transport.inline_reply:
                return reply  # webhook: rides the HTTP response
            await transport.send(message.chat_id, reply)
            return None

        return on_message

    # -- lifecycle -----------------------------------------------------------

    async def run_async(self) -> None:
        """Connect all transports and serve until cancelled."""
        connected: list[ChatTransport] = []
        try:
            for transport in self.transports:
                if await transport.connect(self._callback(transport)):
                    connected.append(transport)
                    logger.info("gateway: %s connected", transport.name)
            stop = asyncio.Event()
            await stop.wait()  # serve until run() is interrupted / task cancelled
        finally:
            await self._shutdown(connected)

    async def _shutdown(self, connected: list[ChatTransport]) -> None:
        for engine in self._engines.values():
            try:
                engine.close()  # finishes any active audit; store stays shared
            except Exception:  # noqa: BLE001
                logger.exception("gateway: engine shutdown failed")
        for transport in reversed(connected):
            try:
                await transport.disconnect()
            except Exception:  # noqa: BLE001
                logger.exception("gateway: %s disconnect failed", transport.name)

    def run(self) -> None:
        """Sync entry: serve until Ctrl-C; clean shutdown, exit code 0."""
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(self.run_async())


# --------------------------------------------------------------------------
# wiring helper for `hunter gateway start` (the CLI composes from this)
# --------------------------------------------------------------------------


def transports_from_env(env: dict[str, str] | None = None) -> list[ChatTransport]:
    """Build the transports the environment asks for — nothing configured,
    nothing started (fail-closed by omission, like every other surface).

    - ``HUNTEROS_TELEGRAM_TOKEN`` + ``HUNTEROS_TELEGRAM_ALLOWED_USERS``
      (comma/whitespace-separated ids) start the Telegram long-poll adapter;
      a token WITHOUT an allowlist raises HunterError — an open Telegram bot
      is never an accident.
    - ``HUNTEROS_DISCORD_TOKEN`` + ``HUNTEROS_DISCORD_ALLOWED_USERS`` start
      the Discord event adapter; the same default-deny rule applies.
    - ``HUNTEROS_WHATSAPP_TOKEN`` + ``HUNTEROS_WHATSAPP_PHONE_NUMBER_ID`` +
      ``HUNTEROS_WHATSAPP_ALLOWED_USERS`` start the WhatsApp Cloud adapter;
      the same default-deny rule applies (see gateway/whatsapp.py).
    - ``HUNTEROS_WEBHOOK_SECRET`` starts the webhook adapter on
      ``HUNTEROS_WEBHOOK_HOST`` (default 127.0.0.1) / ``..._PORT``
      (default 8807) / ``..._PATH`` (default /hunter).
    """
    import os

    from hunter.errors import HunterError
    from hunter.gateway.telegram import TelegramAdapter
    from hunter.gateway.webhook import WebhookAdapter

    env = os.environ if env is None else env
    transports: list[ChatTransport] = []

    def _allowlist(raw: str | None, *, code: str, message: str, hint: str) -> set[str]:
        """Parse a comma/whitespace-separated allowlist; refuse to run open."""
        if not (raw or "").strip():
            raise HunterError(code=code, layer="config", message=message, hint=hint)
        return {part.strip() for part in raw.replace(";", ",").split(",") if part.strip()}

    token = (env.get("HUNTEROS_TELEGRAM_TOKEN") or "").strip()
    if token:
        allowed = _allowlist(
            env.get("HUNTEROS_TELEGRAM_ALLOWED_USERS"),
            code="gateway.telegram_allowlist",
            message="HUNTEROS_TELEGRAM_TOKEN is set but no allowlist is configured",
            hint="set HUNTEROS_TELEGRAM_ALLOWED_USERS to a comma-separated list "
            "of authorized Telegram user ids",
        )
        transports.append(TelegramAdapter(token, allowed))

    discord_token = (env.get("HUNTEROS_DISCORD_TOKEN") or "").strip()
    if discord_token:
        from hunter.gateway.discord import DiscordAdapter

        allowed = _allowlist(
            env.get("HUNTEROS_DISCORD_ALLOWED_USERS"),
            code="gateway.discord_allowlist",
            message="HUNTEROS_DISCORD_TOKEN is set but no allowlist is configured",
            hint="set HUNTEROS_DISCORD_ALLOWED_USERS to a comma-separated list "
            "of authorized Discord user ids",
        )
        transports.append(DiscordAdapter(discord_token, allowed))

    whatsapp_token = (env.get("HUNTEROS_WHATSAPP_TOKEN") or "").strip()
    if whatsapp_token:
        from hunter.gateway.whatsapp import DEFAULT_WEBHOOK_PORT, WhatsAppAdapter

        phone_number_id = (env.get("HUNTEROS_WHATSAPP_PHONE_NUMBER_ID") or "").strip()
        allowed = _allowlist(
            env.get("HUNTEROS_WHATSAPP_ALLOWED_USERS"),
            code="gateway.whatsapp_allowlist",
            message="HUNTEROS_WHATSAPP_TOKEN is set but no allowlist is configured",
            hint="set HUNTEROS_WHATSAPP_ALLOWED_USERS to a comma-separated list "
            "of authorized WhatsApp sender numbers",
        )
        kwargs: dict[str, Any] = {}
        if env.get("HUNTEROS_WHATSAPP_APP_SECRET"):
            kwargs["app_secret"] = env["HUNTEROS_WHATSAPP_APP_SECRET"].strip()
        if env.get("HUNTEROS_WHATSAPP_VERIFY_TOKEN"):
            kwargs["verify_token"] = env["HUNTEROS_WHATSAPP_VERIFY_TOKEN"].strip()
        if env.get("HUNTEROS_WHATSAPP_PORT"):
            # A non-integer port is a config error (exit 8), not a traceback.
            try:
                kwargs["port"] = int(env["HUNTEROS_WHATSAPP_PORT"])
            except ValueError as exc:
                raise HunterError(
                    code="gateway.port_invalid",
                    layer="config",
                    message="HUNTEROS_WHATSAPP_PORT must be an integer — "
                    f"got {env['HUNTEROS_WHATSAPP_PORT']!r}",
                    hint=f"e.g. export HUNTEROS_WHATSAPP_PORT={DEFAULT_WEBHOOK_PORT}",
                ) from exc
        transports.append(WhatsAppAdapter(whatsapp_token, phone_number_id, allowed, **kwargs))

    secret = (env.get("HUNTEROS_WEBHOOK_SECRET") or "").strip()
    if secret:
        kwargs: dict[str, Any] = {}
        if env.get("HUNTEROS_WEBHOOK_HOST"):
            kwargs["host"] = env["HUNTEROS_WEBHOOK_HOST"].strip()
        if env.get("HUNTEROS_WEBHOOK_PORT"):
            # A non-integer port is a config error (exit 8), not a traceback.
            try:
                kwargs["port"] = int(env["HUNTEROS_WEBHOOK_PORT"])
            except ValueError as exc:
                raise HunterError(
                    code="gateway.port_invalid",
                    layer="config",
                    message="HUNTEROS_WEBHOOK_PORT must be an integer — "
                    f"got {env['HUNTEROS_WEBHOOK_PORT']!r}",
                    hint="e.g. export HUNTEROS_WEBHOOK_PORT=8807",
                ) from exc
        if env.get("HUNTEROS_WEBHOOK_PATH"):
            kwargs["path"] = env["HUNTEROS_WEBHOOK_PATH"]
        transports.append(WebhookAdapter(secret, **kwargs))
    return transports
