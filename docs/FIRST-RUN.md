# FIRST-RUN — the exact operator preview

Everything below is **actual rendered output** (captured from a real run in a
throwaway state directory; the one fake is the API key, which is never shown).
Paths are trimmed for readability. Follow it top to bottom for the full
first-run experience.

---

## 1. Install (PowerShell)

```powershell
PS C:\Users\you\Downloads> powershell -ExecutionPolicy Bypass -File install.ps1

HunterOs Harness installer
evidence or nothing

==> Found Python: Python 3.13.7
==> Reusing existing venv: C:\Users\you\.hunteros\venv
==> Upgrading pip (quiet)
==> Local checkout detected — installing editable from C:\Users\you\Downloads\HunterOsHarness
hunteros-harness 0.3.0 installed

Installed. Next steps:

  1. Activate the venv (or use the full path):
       C:\Users\you\.hunteros\venv\Scripts\Activate.ps1
  2. Check the environment:
       hunter doctor
  3. Configure a brain (LLM provider wizard, optional):
       hunter init
  4. Run the one-command demo (local practice target, deterministic scan):
       hunter demo
  5. Open the dashboard:
       hunter tui

Scan only systems you own or are explicitly authorized to test.
```

(`install.sh` prints the same steps for macOS/Linux.)

## 2. Bare `hunter` — the welcome panel

Running `hunter` with no subcommand never dumps help at you — it shows what
to do next:

```
$ hunter
┌────────────────────────────────── hunter ───────────────────────────────────┐
│ HunterOs Harness v0.3.0 — evidence-first security auditing                  │
│                                                                             │
│ every finding is proven by a hash-chained ledger, or it does not exist      │
│                                                                             │
│ next steps:                                                                 │
│   hunter init    — configure a brain (LLM provider, key, model) in one      │
│ wizard                                                                      │
│   hunter demo    — first blood on a local practice target, no keys needed   │
│   hunter doctor  — verify the environment end to end                        │
│                                                                             │
│ help: hunter --help · scan only what you own                                │
└──────────────────────────── Evidence or Nothing ────────────────────────────┘
```

(`hunter --help` still prints the full command dump.)

## 3. `hunter doctor` — trust, then verify

```
$ hunter doctor
HunterOs Harness doctor — hunter 0.3.0
  OK  python 3.13.7 on Windows
  OK  dep:typer 0.27.2
  OK  dep:rich 15.0.0
  OK  dep:textual 8.2.8
  OK  dep:httpx 0.28.1
  OK  state-dir C:\Users\you\project\.hunter\ledger.db — 0 run(s)
  OK  ledger-chain empty ledger
  OK  engines deterministic, llm, mock
  OK  workflow pipeline + demo ready
  OK  llm-config defaults, no config file
  OK  llm-tier basic — pin a brain with agent.tier or $HUNTEROS_TIER (basic,
advanced, planner, exploit, verify, utility)
  OK  llm-model unset — set HUNTEROS_MODEL or model_tiers.planner.model in
~/.hunteros/config.yaml
  OK  llm-keys no providers configured
  OK  llm-litellm 1.100.1
  OK  chat-db quick_check ok — 68 session(s)
All checks passed.
```

Red `FAIL` rows block (exit 1); yellow rows are opt-in gaps that never do.
`hunter doctor --json` emits `{"checks": [...], "ok": true}` for scripts;
`--live` probes each configured provider's endpoint.

## 4. `hunter init` — configure a brain in one wizard

Interactive (every prompt has a safe default; failures become notes, never
crashes):

```
$ hunter init
hunter init — first-run wizard
config target: C:\Users\you\.hunteros\config.yaml
step 1/6 environment: Python 3.13.7
  litellm installed — the LLM brain is available
step 2/6 tier: advanced
providers:
  1. openai       — OpenAI official API
  2. anthropic    — Claude models
  3. openrouter   — 400+ models behind one key
  4. deepseek     — DeepSeek V3 / R1
  5. groq         — very fast open-model inference
  6. together     — open models, one key
  7. ollama       — local, keyless — nothing leaves your machine
  8. lmstudio     — local OpenAI-compatible server, keyless
  9. vllm         — self-hosted OpenAI-compatible server, keyless
  10. custom       — any OpenAI-compatible base URL
provider [1]: 3
step 3/6 provider: openrouter (https://openrouter.ai/api/v1)
step 4/6 key: OPENROUTER_API_KEY
  set OPENROUTER_API_KEY in a NEW shell (the key itself is never printed here):
  PowerShell: [Environment]::SetEnvironmentVariable('OPENROUTER_API_KEY','<key>','User')
  bash:       echo 'export OPENROUTER_API_KEY=<key>' >> ~/.bashrc
step 5/6 model: planner=anthropic/claude-sonnet-4.5 verify=anthropic/claude-3.5-haiku
step 6/6 live test: skipped — no key yet
wrote C:\Users\you\.hunteros\config.yaml
notes:
  - live test skipped — OPENROUTER_API_KEY is not set
next: hunter doctor · hunter demo · hunter chat
```

After setting the key in a NEW shell, the live test dials once (1 token):

```
step 6/6 live test: dialing with a 1-token ping...
  live test: OK (842 ms)
```

Non-interactive, for scripts and dotfiles:

```
$ hunter init --provider openrouter --yes
```

`--yes` refuses to overwrite an existing config (exit 2, name the path) —
pass `--path` to write elsewhere. The key itself is NEVER echoed: the wizard
prints the export lines with a `<key>` placeholder, and an optional paste-now
goes into the config file inline (with a "prefer the env var" warning).

## 5. `hunter demo` — first blood, no keys

```
$ hunter demo
             Demo run R-74ac00038e2a — target PracticeVault :56369
┌──────────┬──────────┬───────────────────────────────┬───────────────────────┐
│ severity │ status   │ finding                       │ endpoint              │
├──────────┼──────────┼───────────────────────────────┼───────────────────────┤
│ critical │ verified │ Unauthenticated               │ POST /transfer        │
│          │          │ state-changing action         │                       │
│ high     │ verified │ Auth bypass via forgeable     │ GET /admin            │
│          │          │ plaintext role cookie         │                       │
│ high     │ verified │ Path traversal in file        │ GET /download         │
│          │          │ download                      │                       │
│ high     │ verified │ Reflected XSS in search       │ GET /search           │
│          │          │ parameter                     │                       │
│ high     │ verified │ Sensitive file exposed: User  │ GET /backup/users.sql │
│          │          │ database backup               │                       │
│ medium   │ verified │ Open redirect via url         │ GET /goto             │
│          │          │ parameter                     │                       │
│ medium   │ verified │ SQL error disclosure on login │ POST /login           │
│ low      │ verified │ Session cookie without        │ POST /login           │
│          │          │ HttpOnly/Secure flags         │                       │
│ low      │ verified │ Directory listing enabled     │ GET /static/          │
│ info     │ verified │ Missing security response     │ GET /                 │
│          │          │ headers                       │                       │
└──────────┴──────────┴───────────────────────────────┴───────────────────────┘
FIRST BLOOD: 9/9 (100%) — verified 10, candidates 0
score ✓ | recon ✓ | classify ✓ | hunting ████████████ 12/12 | verify ✓ | report ✓ | retro ✓
ledger: 36 requests, chain ok (102 events) — next: hunter report --run R-74ac00038e2a
```

The `score ✓ | recon ✓ | ... | retro ✓` line is the phase pipeline — every
transition is a ledger event with an exit gate, so the timeline is evidence,
not decoration.

## 6. `hunter chat` — talk to the brain

```
$ hunter chat
╭─────────────── hunter chat ───────────────╮
│ HUNTEROS — Evidence or Nothing            │
│ v0.3.0  |  tier: advanced  |  model:      │
│ anthropic/claude-sonnet-4.5               │
│ session: S-9f2c…                          │
│ No fabricated claims: a finding exists    │
│ only when the hash-chained ledger can     │
│ replay its evidence.                      │
│ Type /help for commands — free text talks │
│ to the model.                             │
╰──────────────── Evidence or Nothing ───────╯
hunter> scan the practice target and tell me what is verified
recon complete: 2 verified findings — evidence is in the ledger.
hunter> /quit
session saved — evidence or nothing.
```

## 7. Custom & third-party providers

Any OpenAI-compatible endpoint is a first-class provider:

```
$ hunter config provider add groq
$ hunter config provider add corp-vllm --base-url http://llm.corp.example.com/v1 --default-model qwen2.5-32b-instruct
$ hunter config provider list
                                 LLM providers
┌───────────┬────────────────────────┬────────────────────────┬────────────────────┐
│ name      │ key source             │ base_url               │ default model      │
├───────────┼────────────────────────┼────────────────────────┼────────────────────┤
│ corp-vllm │ keyless                │ http://llm.corp.exampl │ qwen2.5-32b-instr… │
│ groq      │ env:GROQ_API_KEY (not  │ -                      │ -                  │
│           │ set)                   │                        │                    │
└───────────┴────────────────────────┴────────────────────────┴────────────────────┘
$ hunter config provider test corp-vllm
corp-vllm: OK (842 ms)
```

`provider remove <name>` refuses while `model_tiers.*.provider` or
`fallback_providers` still reference it (exit 2, naming the referencing keys)
— `--force` overrides. Full config examples (OpenRouter, DeepSeek, Groq,
Together, Ollama, LM Studio, vLLM, corp proxy + fallback): see the
**Custom & third-party providers** section of [docs/LLM.md](LLM.md).

## 8. Errors — every failure has a name and a location

**Scope is fail-closed** (exit 2, the rule is named, no widening fix):

```
$ hunter scan http://not-my-server.example.com/
BLOCKED: target 'not-my-server.example.com' is not localhost. Pass --scope
scope.json with an authorized scope manifest (e.g. {"name": "client-x",
"hosts": ["example.com"]}).
```

**Classified errors carry a `where:` line** (this one: exit 8, config):

```
$ hunter config show
[ERROR config] config file C:\Users\you\.hunteros\config.yaml is not valid YAML:
ParserError (line 5, column 1)
Hint: fix the YAML syntax — indent with spaces, quote strings with special chars
where: hunter/llm/config.py:242
```

A missing provider key is exit 4 (`key missing (ENV_NAME)`); auth/billing
failures from the provider surface as `[ERROR auth] …` with their hint.

**Unexpected errors never traceback by default** (exit 1):

```
$ hunter runs
[ERROR engine] unexpected RuntimeError: simulated crash for the docs
[report] re-run with --verbose for the full traceback, or file an issue:
https://github.com/zaaaxx11/HunterOsHarness/issues
```

Asked for, the traceback goes to STDERR and only there:

```
$ hunter --verbose runs
[ERROR engine] unexpected RuntimeError: simulated crash for the docs
[report] re-run with --verbose for the full traceback, or file an issue:
https://github.com/zaaaxx11/HunterOsHarness/issues
Traceback (most recent call last):
  ...
RuntimeError: simulated crash for the docs
```

`--verbose` is a global flag (or `HUNTEROS_VERBOSE=1`). Ctrl-C anywhere is
`[interrupted]` + exit 130 — never a traceback.

---

## Where things live

| What | Where |
| ---- | ----- |
| Config | `~/.hunteros/config.yaml` (or `$HUNTEROS_CONFIG`) — `hunter config example` |
| State / ledger | `./.hunter/ledger.db` (or `$HUNTER_STATE_DIR`) |
| Chat sessions | `~/.hunteros/chat.db` (or `$HUNTEROS_CHAT_DB`) — hash-chained, undo-safe |
| Report | `hunter report` — markdown from ledger rows only |
