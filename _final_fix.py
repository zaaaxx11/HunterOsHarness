"""Final fix: file attachment = auto hunt target. No JSON parsing needed.

Flow:
1. File uploaded → injected into prompt as [📎 name]```...```
2. User says /hunt <anything> OR just "find vulns"
3. app.py sets session.target = file path
4. Engine hunts the file directly
"""

p = "src/hunter/gateway/app.py"
s = open(p).read()

# After file injection, if user says anything about hunting, auto-set target
old = """text = message.text
            has_file = message.attachment_path is not None
            if has_file:"""

new = """text = message.text
            has_file = message.attachment_path is not None

            # A file IS a hunt target. When the user attaches a file and says
            # any variant of "hunt" / "find" / "audit", set the session target
            # to the file path so the engine hunts it directly — no JSON parsing,
            # no URL extraction, no round-trip.
            if has_file:
                raw_lower = (message.text or "").lower()
                wants_hunt = any(
                    kw in raw_lower
                    for kw in ("/hunt", "hunt", "find", "audit", "scan", "vuln", "rce", "exploit")
                )
                if wants_hunt:
                    try:
                        engine = self.engine_for(
                            "telegram:" + message.chat_id
                        )
                        if hasattr(engine, "session"):
                            engine.session.target = message.attachment_path
                            engine.session.goals = {
                                "_description": message.text.strip() if message.text.strip() else "audit attached file",
                                "findings-min": 5,
                            }
                            engine.session.wall_seconds = 21600
                            engine.session.idle_seconds = 15
                            engine.session.budget = 0.0
                            engine.session.running = True
                            import threading
                            threading.Thread(
                                target=engine._run_hunt,
                                args=(engine.session,),
                                daemon=True,
                                name="hunt-worker-file",
                            ).start()
                            return (
                                f"🔥 hunting attached file: "
                                f"{message.attachment_name or 'unknown'}\\n"
                                f"  target: {message.attachment_path}\\n"
                                f"  /status · /pause · /stop"
                            )
                    except Exception:
                        pass  # fall through to normal handling

            if has_file:"""

s = s.replace(old, new, 1)

with open(p, "w") as f:
    f.write(s)

import py_compile
py_compile.compile(p, doraise=True)
print("OK")