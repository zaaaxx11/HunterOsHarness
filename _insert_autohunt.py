"""Insert auto-hunt block into app.py on VPS."""
p = 'src/hunter/gateway/app.py'
s = open(p).read()

# Find the anchor
idx = s.index('            text = message.text')

# Build the auto-hunt block
block = '''
            # AUTO-HUNT: file attachment = hunt target immediately
            has_file = message.attachment_path is not None
            if has_file:
                raw_lower = (message.text or "").lower()
                wants_hunt = any(kw in raw_lower for kw in (
                    "/hunt", "hunt", "find", "audit", "scan", "vuln", "rce", "exploit"
                ))
                if wants_hunt:
                    try:
                        engine = self.engine_for("telegram:" + message.chat_id)
                        if hasattr(engine, "session"):
                            engine.session.target = message.attachment_path
                            engine.session.goals = {
                                "_description": (message.text or "").strip() or "audit attached file",
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
                                "\U0001f525 hunting attached file: "
                                + (message.attachment_name or "unknown")
                                + "\\ntarget: " + message.attachment_path
                                + "\\n/status \\u00b7 /pause \\u00b7 /stop"
                            )
                    except Exception:
                        pass  # fall through to normal handling

'''
s = s[:idx] + block + s[idx:]
with open(p, 'w') as f:
    f.write(s)
print('INSERTED')