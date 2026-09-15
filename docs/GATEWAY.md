# Gateway — Telegram, Discord, WhatsApp, and webhook front-ends

The gateway puts the HunterOs agent behind messaging front-ends with the
same governance as the local REPL: same slash commands, same scope gate,
same ledger. The gateway is a **rendering surface** — it never creates
truth. Findings are ledger-only, and the scope gate is enforced in the HTTP
client below the agent, exactly as in a local run.

Four transports:

- **Telegram** — direct messages to a bot you own. User-facing, human-friendly.
- **Discord** — messages to a bot in your server (`hunteros-harness[discord]`).
- **WhatsApp** — the Meta Cloud API over a loopback webhook, HMAC-verified inbound.
- **Webhook** — HTTP POST with HMAC signing. Machine-to-machine: CI, cron,
  internal tools.

Install the transport extra you need:

```bash
pip install 'hunteros-harness[telegram]'   # python-telegram-bot
pip install 'hunteros-harness[discord]'    # discord.py
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

## Discord

### 1. Create the bot (~2 minutes)

1. In the [Discord Developer Portal](https://discord.com/developers/applications),
   create an application → **Bot** → copy the token (treat it like an API key).
2. Enable the **MESSAGE CONTENT** intent (the gateway reads message text).
3. Invite the bot to your server with the `bot` scope (OAuth2 → URL Generator).

### 2. Configure

```bash
pip install 'hunteros-harness[discord]'
export HUNTEROS_DISCORD_TOKEN="MTA..."            # from the developer portal
export HUNTEROS_DISCORD_ALLOWED_USERS="42,7"      # numeric Discord user ids, CSV
```

`HUNTEROS_DISCORD_ALLOWED_USERS` is a comma-separated list of **numeric
Discord user ids** (Developer Mode → right-click a user → Copy User ID).
The allowlist is **default-deny** — an empty or unset list refuses everyone,
and a token set without an allowlist is a config error, never an open bot.

### 3. Start

```bash
hunter gateway start
```

Messages are chunked at Discord's 2000 UTF-16-unit limit; direct messages
map to `dm`, other channel types map to their type. Denied senders cost one
warning log line — no reply, nothing recorded.

---

## Approvals over chat

Dangerous tools never run on trust on any surface. When the agent calls
`shell_exec`, the gate stores a pending approval request, blocks the call,
and tells the model the request id:

```
BLOCKED: tool 'shell_exec' requires user approval. Request id: A-1a2b3c4d
(expires in 300s). Ask the user to reply /approve A-1a2b3c4d — do not
retry before approval.
```

You — an allowlisted operator — reply like any other message:

```
/approve A-1a2b3c4d   → "approval A-1a2b3c4d granted — the agent will be nudged to retry"
/deny A-1a2b3c4d      → "approval A-1a2b3c4d denied"
```

Approvals are **single-use** (one decision = one retry), **expire** after
300 seconds, and never widen the scope gate. Every local-system change —
including catastrophic commands (`rm -rf`, disk formatting, fork bombs, …) —
requires explicit approval in every mode: the gate files a pending request
(`approval.catastrophic`) and only an explicit `/approve` permits exactly one
execution. Read-only recon commands auto-allow in hunter mode; interpreters
and everything unknown count as mutating.

---

## WhatsApp (Cloud API)

The WhatsApp adapter talks to Meta's Graph API (`v21.0`) and receives
inbound messages on a **loopback-only** webhook.

### 1. Meta app setup (~10 minutes)

1. Create a Meta app, add the WhatsApp product, and note the **phone number
   id** and a **permanent access token**.
2. Point the webhook subscription at your loopback-forwarded endpoint
   (`/whatsapp`), set a verify token, and subscribe to the `messages` field.

### 2. Configure

```bash
export HUNTEROS_WHATSAPP_TOKEN="EAAG..."            # permanent access token
export HUNTEROS_WHATSAPP_PHONE_NUMBER_ID="123456"   # phone number id
export HUNTEROS_WHATSAPP_ALLOWED_USERS="15551234567" # sender numbers, CSV — default-deny
export HUNTEROS_WHATSAPP_APP_SECRET="..."           # REQUIRED for signed inbound verification
export HUNTEROS_WHATSAPP_VERIFY_TOKEN="..."         # Meta hub verification string
export HUNTEROS_WHATSAPP_PORT="8808"                # loopback webhook port (default 8808)
```

The trio (token + phone number id + allowlist) is required; a missing
allowlist is a config error, never an open bot.

### Inbound security model

- `GET /whatsapp` answers Meta's hub verification: `hub.mode=subscribe` and
  your verify token → `hub.challenge` echoed verbatim; anything else → 403.
- `POST /whatsapp` validates `X-Hub-Signature-256` (hex HMAC-SHA256 of the
  **raw** body with the app secret, timing-safe compare) **before** any
  parsing: missing, malformed, or forged signatures get 403 and the handler
  is never called.
- Non-text payloads (receipts, `status` callbacks) are ignored; a sender
  not in the allowlist costs one warning log line and nothing runs.
- Outbound messages are chunked at WhatsApp's 4096-character limit; the
  bind is `127.0.0.1` only — terminate TLS at your tunnel, never on the
  loopback socket itself.

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
> entries → nobody. No `HUNTEROS_DISCORD_ALLOWED_USERS` or
> `HUNTEROS_WHATSAPP_ALLOWED_USERS` → nobody. No webhook secret configured →
> nothing signed verifies. An unknown sender, a stale timestamp, a bad
> signature, or an unsigned WhatsApp POST is a refusal, never a queue entry.
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
