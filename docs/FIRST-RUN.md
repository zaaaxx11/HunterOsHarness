# FIRST-RUN — the exact operator preview

Everything below is **actual rendered output** (captured from real runs in
throwaway state directories; the one fake is the API key, which is never
shown). Paths are trimmed for readability. Follow it top to bottom for the
full first-run experience.

---

## 1. Install (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.sh | bash
# Windows (PowerShell):
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/zaaaxx11/HunterOsHarness/main/install.ps1 | iex"
```

The installer prints its ASCII banner, registers `hunter` + `hunt` shims in
`~/.hunteros/bin`, appends a tagged PATH block to your shell rc (idempotent —
re-running never duplicates it), and on an interactive terminal launches the
onboarding wizard. Real transcript (macOS/Linux, trimmed):

```
 _   _   _   _   _   _   _____   _____   ____
| | | | | | | | | \ | | |_   _| | ____| |  _ \   / _ \  / ____|
| |_| | | | | | |  \| |   | |   |  _|   | |_) | | | | | \___ \
|_| |_|  \___/  |_| \_|   |_|   |_____| |_| \_\  \___/  |____/
  HunterOs Harness - evidence or nothing

==> Found Python: Python 3.13.7
==> Reusing existing venv: /home/you/.hunteros/venv
==> Upgrading pip (quiet)
==> Installing hunteros-harness from PyPI
hunteros-harness 0.4.0 installed
    shims written to /home/you/.hunteros/bin (hunter, hunt)
    PATH registered in /home/you/.bashrc — open a NEW shell or: source /home/you/.bashrc
==> Launching the onboarding wizard
    ... (the `hunter init` wizard from section 4 runs here)

Installed. Next steps:

  1. Open a NEW shell (PATH updated), then run:
       hunter
     The onboarding wizard configures your brain in about a minute -
     then `hunter chat` talks to it. (`hunt` works anywhere `hunter` does.)
  2. Coming in a later release:
       hunter hunt <url> - one-command hunt on an authorized target.

Scan only systems you own or are explicitly authorized to test.
```

Flags: `--skip-setup` (or `-SkipSetup`) skips the wizard; `--dry-run`
(`-DryRun`) writes only the shims + PATH block — no python/pip/network.
Re-running the installer is an **update**: venv reused, packages refreshed,
shims rewritten, PATH deduped, and the wizard is skipped when a config
already exists.

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
advanced, orchestrator, hunter, verifier, utility)
  OK  llm-model unset — set HUNTEROS_MODEL or model_tiers.orchestrator.model in
~/.hunteros/config.yaml
  OK  llm-keys no providers configured
  OK  llm-litellm 1.100.1
  OK  chat-db quick_check ok — 68 session(s)
All checks passed.
```

Red `FAIL` rows block (exit 1); yellow rows are opt-in gaps that never do.
`hunter doctor --json` emits `{"checks": [...], "ok": true}` for scripts;
`--live` probes each configured provider's endpoint.

## 4. `hunter init` — the onboarding wizard (v2)

Interactive (every prompt has a safe default; failures become notes, never
crashes; an empty reply always takes the default). Real transcript, trimmed
(the pasted key is never echoed — the one fake in this doc):

```
$ hunter init
hunter init — onboarding wizard
config target: C:\Users\you\.hunteros\config.yaml
About 60 seconds. Writes C:\Users\you\.hunteros\config.yaml (+ keys.env only if you paste a key).
Your key is sent nowhere except the provider you pick.
How should models be assigned?
  1. Auto — one model for every role (fastest setup)
  2. Advanced — pick a model per role (orchestrator / hunter / verifier / utility)
mode [1]: 1
step 1/7 mode: auto
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
provider [1]: 5
step 2/7 provider: groq
key source for groq:
  1. Paste the key now — stored in C:\Users\you\.hunteros\keys.env, never echoed, never in the config
  2. Set the env var GROQ_API_KEY yourself (recommended for shared machines)
key [1]: 1
paste the GROQ_API_KEY key (input hidden): ********
step 4/7 model: orchestrator=llama-3.3-70b-versatile
Enable web automation (browser-driven hunting)? [y/N]:
step 5/7 browser: off
step 6/7 tools:
  OK  python 3.13.7 on Windows
  OK  state-dir C:\Users\you\project\.hunter\ledger.db — 0 run(s)
wrote C:\Users\you\.hunteros\keys.env
wrote C:\Users\you\.hunteros\config.yaml
step 7/7 smoke test: dialing groq/llama-3.3-70b-versatile with a 1-token ping...
  smoke test: OK (742 ms)
╭────────────────────────────────────────── done ──────────────────────────────────────────╮
│ config:  C:\Users\you\.hunteros\config.yaml                                              │
│ keys:    C:\Users\you\.hunteros\keys.env (GROQ_API_KEY)                                  │
│ brain:   groq / llama-3.3-70b-versatile                                                  │
│ tier:    basic                                                                           │
│ browser: off                                                                             │
│ next:                                                                                    │
│   hunter chat        — talk to your brain                                                │
│   hunter demo        — first blood, no keys needed                                       │
│   hunter doctor      — verify the environment                                            │
╰────────────────────────────────── Evidence or Nothing ───────────────────────────────────╯
Scan only systems you own or are explicitly authorized to test.
```

What happened: the pasted key went to `~/.hunteros/keys.env` (0600 POSIX,
loaded at CLI startup — real env vars win), and the config carries only the
env-var NAME. Auto mode gives all four roles (orchestrator / hunter / verifier /
utility) the same model; answer `2` at the mode prompt to pick one per role.
Picking `custom` probes your base URL for its API shape (chat vs responses)
and offers the model ids it advertises at `GET {base}/models`. Every failure
(a dead endpoint, a refused key) becomes a note under the panel — the run
still exits 0 and still writes a valid config.

Non-interactive, for scripts and dotfiles — the classic v1 flow:

```
$ hunter init --provider openrouter --yes
```

`--provider`/`--yes` keep the original behavior: defaults from the provider
table, no prompts, exit 2 (with the path named) if `--yes` would overwrite an
existing config — pass `--path` to write elsewhere.

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

Any OpenAI-compatible endpoint is a first-class provider. Run
`hunter provider add` (no name) for the interactive wizard — provider pick,
key capture, endpoint auto-detect, model auto-add, role assignment — or script
it with flags:

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
| Keys | `~/.hunteros/keys.env` (0600; env vars win) — written by the wizard when a key is pasted |
| Shims | `~/.hunteros/bin/hunter` + `hunt` (Windows: `%USERPROFILE%\.hunteros\bin\*.cmd`) |
| State / ledger | `./.hunter/ledger.db` (or `$HUNTER_STATE_DIR`) |
| Chat sessions | `~/.hunteros/chat.db` (or `$HUNTEROS_CHAT_DB`) — hash-chained, undo-safe |
| Report | `hunter report` — markdown from ledger rows only |
