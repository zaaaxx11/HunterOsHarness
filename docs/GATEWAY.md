# Gateway — Telegram and webhook front-ends

The gateway puts the HunterOs agent behind messaging front-ends with the
same governance as the local REPL: same slash commands, same scope gate,
same ledger. The gateway is a **rendering surface** — it never creates
truth. Findings are ledger-only, and the scope gate is enforced in the HTTP
client below the agent, exactly as in a local run.

Two transports:

- **Telegram** — direct messages to a bot you own. User-facing, human-friendly.
- **Webhook** — HTTP POST with HMAC signing. Machine-to-machine: CI, cron,
  internal tools.

Install the transport extra you need:

```bash
pip install 'hunteros-harness[telegram]'   # python-telegram-bot
```

---

## Telegram

### 1. Create the bot (~2 minutes)

1. In Telegram, message **@BotFather** → `/newbot`, pick a name and a
   username (must end in `bot`).
2. BotFather replies with a token like `123456789:AAE...`. That is the
   bot token — treat it like an API key.

### 2. Configure

```bash
export HUNTEROS_TELEGRAM_TOKEN="123456789:AAE..."
export HUNTEROS_TELEGRAM_ALLOWED_USERS="111111111,222222222"
```

`HUNTEROS_TELEGRAM_ALLOWED_USERS` is a comma-separated list of **numeric
Telegram user ids** (get yours from @userinfobot). The allowlist is
**default-deny**: an empty or unset list refuses everyone. Never allow by
username — usernames change; ids do not.

### 3. Start

```bash
hunter gateway start
```

(The adapter reads `HUNTEROS_TELEGRAM_TOKEN` / `HUNTEROS_WEBHOOK_SECRET` from
the environment; there is no per-transport flag.)

### Message flow

- **Allowed user** → the message becomes an agent turn; the reply is the
  agent's yield (`respond_to_user`) or the turn result. Slash commands work
  identically to the local REPL (`/help`, `/model`, `/usage`, …).
- **Denied user** → one warning log line; **no reply, nothing recorded** —
  no run, no ledger event, no session. A denied sender learns nothing, and
  the ledger learns nothing either.
- **Unknown command / bad input** → a classified `HunterError` surface
  (2 lines max, no traceback, no secrets), never a stack dump.

While a turn is running, a new message from the same chat gets **"still
working…"** — the turn lease prevents overlapping agent runs; the new
message waits, it does not interrupt.

---

## Webhook

Machine front-end: your CI or cron posts a signed JSON body, the gateway
runs the agent turn, and the response carries the result.

### HMAC signing spec

| Element | Value |
| ------- | ----- |
| Timestamp header | `X-Hunter-Timestamp` — unix seconds; **±300 s** window |
| Signature header | `X-Hunter-Signature` — lowercase **hex** `hmac-sha256(secret, "{ts}.{body}")` where `{ts}` is the timestamp header string and `{body}` is the **exact raw request body** |
| Body cap | **64 KB** — larger bodies are rejected before verification |
| Secret | Set on the gateway process (e.g. `HUNTEROS_WEBHOOK_SECRET`); requests with an unconfigured secret are rejected |

Verification is constant-time and fail-closed: missing headers, stale
timestamp, body over the cap, or a bad signature → a `401`/`403`-class
refusal, nothing recorded.

**Replay protection:** the timestamp window alone is not enough — the
gateway also remembers every accepted signature for the window, so
re-posting the exact same signed request is refused. Re-sending the same
job means re-signing it with a fresh timestamp.

**INSECURE_NO_AUTH:** there is a development mode that disables signature
verification — it is **loopback-only** (binds/accepts `127.0.0.1`/`::1`
only; `127.0.0.2` and other loopback-adjacent addresses are refused) and
exists so you can try the flow without a secret. It refuses to start
against any non-loopback bind. If it sounds like a footgun, that is because
it is; never terminate TLS at a proxy in front of it and expect the gateway
to know the difference.

### Sign and send — curl

```bash
TS=$(date +%s)
BODY='{"text":"scan the practice target and report verified findings"}'
SECRET="your-webhook-secret"
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')

curl -X POST http://127.0.0.1:8080/hunter \
  -H "Content-Type: application/json" \
  -H "X-Hunter-Timestamp: $TS" \
  -H "X-Hunter-Signature: $SIG" \
  -d "$BODY"
```

### Sign and send — Python

```python
import hashlib, hmac, json, time
import urllib.request

SECRET = b"your-webhook-secret"
body = json.dumps({"text": "scan the practice target"}).encode()
ts = str(int(time.time()))
sig = hmac.new(SECRET, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "http://127.0.0.1:8080/hunter",
    data=body,
    headers={
        "Content-Type": "application/json",
        "X-Hunter-Timestamp": ts,
        "X-Hunter-Signature": sig,
    },
)
print(urllib.request.urlopen(req, timeout=120).read().decode())
```

Timing note: sign `{ts}.{body}` over the **raw** bytes you send — if you
re-serialize JSON after signing, the signature will not match. The same
turn-lease rule applies as in Telegram: a second request while a turn is
running gets the "still working…" acknowledgment, not a second concurrent
agent.

---

## SECURITY — what the gateway does not change

> **Allowlists are fail-closed.** No `HUNTEROS_TELEGRAM_ALLOWED_USERS`
> entries → nobody. No webhook secret configured → nothing signed verifies.
> An unknown sender, a stale timestamp, or a bad signature is a refusal,
> never a queue entry.
>
> **The scope gate is still in code.** A Telegram message or a webhook
> payload is a *user message* — it cannot expand the authorized scope. The
> fail-closed check runs in the HTTP client before the socket opens, below
> the agent, exactly as in a local run. "Scan this other host" from an
> allowed user is `BLOCKED [scope.target_out_of_scope]` like anywhere else.
>
> **Findings are still ledger-only.** The gateway renders from ledger rows;
> it cannot mint findings, mark evidence verified, or edit the trail. What
> you read in the chat is a view of the same hash-chained ledger whose
> chain `hunter doctor` recomputes and reports on every run.
