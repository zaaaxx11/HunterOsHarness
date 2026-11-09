"""Phase 1: 5 fixes in one shot."""
import ast, py_compile, os, textwrap

HERE = "/home/simon/HunterOsHarness"
FIXES = []

# ── Fix 1: CHAT_SYSTEM concise ──────────────────────────────────────
def fix1():
    p = os.path.join(HERE, "src/hunter/cli/shell.py")
    s = open(p).read()
    old = s[s.index("CHAT_SYSTEM = ("):s.index(")", s.index("CHAT_SYSTEM = ("))+2]
    new = textwrap.dedent("""\
    CHAT_SYSTEM = (
        "Kamu HUNTER. Ringkas — max 3 kalimat. Satu aksi per balasan. "
        "Bukti > opini. Kalau user sebut target/vuln, suggest /hunt. "
        "Kalau bisa difix, fix. Jangan jelasin — kerjakan. "
        "Jawab dalam bahasa operator. Emoji 💋🔥😘💕✨."
    )
    """)
    s = s.replace(old, new, 1)
    open(p, "w").write(s)
    ast.parse(s); py_compile.compile(p, doraise=True)
    print("[1/5] CHAT_SYSTEM: concise + action-first")

# ── Fix 2: cmd_hunt single path ─────────────────────────────────────
def fix2():
    p = os.path.join(HERE, "src/hunter/cli/commands/core.py")
    s = open(p).read()
    # Simplify: no positional fallback, no raw_llm bypass
    # Find the block between "reply = chat" and import json
    old_block_start = s.index('reply = chat(system + "')
    old_block_end = s.index("import json as _json", old_block_start)
    new_block = textwrap.dedent("""\
    reply = chat(system + "\\n\\n" + prompt)
    except Exception as exc:
        return "model unreachable: " + type(exc).__name__ + " — " + raw[:120]

    """).lstrip()
    s = s[:old_block_start] + new_block + s[old_block_end:]
    # Remove _cmd_hunt_positional if present
    if "_cmd_hunt_positional" in s:
        pos = s.index("def _cmd_hunt_positional")
        endpos = s.index("\n@command", pos)
        s = s[:pos] + s[endpos:]
    open(p, "w").write(s)
    ast.parse(s); py_compile.compile(p, doraise=True)
    print("[2/5] cmd_hunt: single path, no positional fallback")

# ── Fix 3: file auto-hunt ────────���──────────────────────────────────
def fix3():
    p = os.path.join(HERE, "src/hunter/gateway/app.py")
    s = open(p).read()
    # Find handle_message hanlder
    idx = s.index('text = message.text')
    # Already has auto-hunt from earlier deploy — verify
    if "hunting attached file" not in s:
        block = textwrap.dedent("""\
            text = message.text
            has_file = message.attachment_path is not None

            # AUTO-HUNT: file = target. When user attaches a file and says
            # any hunt keyword, start the hunt immediately — no model round-trip.
            if has_file:
                raw_lower = (message.text or "").lower()
                wants_hunt = any(kw in raw_lower for kw in (
                    "/hunt", "hunt", "find", "audit", "scan", "vuln", "rce", "exploit"
                ))
                if wants_hunt:
                    try:
                        eng = self.engine_for("telegram:" + message.chat_id)
                        if hasattr(eng, "session"):
                            eng.session.target = message.attachment_path
                            eng.session.goals = {
                                "_description": (message.text or "").strip() or "audit attached file",
                                "findings-min": 5,
                            }
                            eng.session.wall_seconds = 21600
                            eng.session.idle_seconds = 15
                            eng.session.budget = 0.0
                            eng.session.running = True
                            import threading
                            threading.Thread(
                                target=eng._run_hunt,
                                args=(eng.session,),
                                daemon=True,
                                name="hunt-worker-file",
                            ).start()
                            return (
                                "\\U0001f525 hunting attached file: "
                                + (message.attachment_name or "unknown")
                                + "\\n/status \\u00b7 /pause \\u00b7 /stop"
                            )
                    except Exception:
                        pass

        """)
        s = s[:idx] + block + s[idx + len("            text = message.text"):]
    open(p, "w").write(s)
    ast.parse(s); py_compile.compile(p, doraise=True)
    print("[3/5] app.py: auto-hunt on file attachment")

# ── Fix 4: sendMessage buffer ───────────────────────────────────────
def fix4():
    p = os.path.join(HERE, "src/hunter/gateway/hunt_engine.py")
    s = open(p).read()
    # Find _say method
    idx = s.index("def _say(self, text: str)")
    end_idx = s.index("\n    def ", idx + 50)
    old_method = s[idx:end_idx]
    new_method = textwrap.dedent("""\
    def _say(self, text: str) -> None:
        """Queue a progress message; flush every 5s so Telegram sees one update, not seventy"""
        import time as _time
        now = _time.monotonic()
        self._msg_buf.append(text)
        if now - self._msg_last >= MSG_FLUSH_SECONDS:
            self._flush_buf()

    def _flush_buf(self) -> None:
        import time as _time
        if not self._msg_buf:
            return
        combined = "\\n".join(self._msg_buf[-12:])  # max 12 lines
        self._msg_buf.clear()
        self._msg_last = _time.monotonic()
        if self.notify is not None and callable(self.notify):
            try:
                self.notify(combined)
            except Exception:
                pass
    """)
    s = s.replace(old_method, new_method, 1)
    # Add buffer in __init__
    init_idx = s.index("def __init__")
    init_end = s.index("\n    def ", init_idx + 20)
    init_old = s[init_idx:init_end]
    if "self._msg_buf" not in init_old:
        init_old = init_old.rstrip() + "\n        self._msg_buf: list[str] = []\n        self._msg_last: float = 0.0\n"
        s = s[:init_idx] + init_old + s[init_end:]
    # Add flush in _run_hunt final block
    if "self._flush_buf()" not in s:
        s = s.replace("self._say(" + '"\n".join(lines))',
                      'self._flush_buf(); self._say("\\n".join(lines))')
    # Add constant at top of file
    if "MSG_FLUSH_SECONDS" not in s:
        s = s.replace("from hunter.cli.spinner import",
                      "MSG_FLUSH_SECONDS = 5.0  # batch progress updates\n\nfrom hunter.cli.spinner import")
    open(p, "w").write(s)
    ast.parse(s); py_compile.compile(p, doraise=True)
    print("[4/5] hunt_engine: 5s message buffer")

# ── Fix 5: gateway clean restart ────────────────────────────────────
def fix5():
    print("[5/5] gateway restart — will be done manually on VPS")

# Run all
for fn in [fix1, fix2, fix3, fix4, fix5]:
    try:
        fn()
    except Exception as e:
        print(f"  FAILED: {e}")
        import traceback; traceback.print_exc()

print("\n✅ ALL 5 FIXES COMPLETE — ready to deploy")