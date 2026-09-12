# LLM — bring your own key (BYOK) guide

v0.2 gives HunterOs an LLM brain: agent chat, model-driven audit loops, and
tier routing — mounted on the same evidence contract as the deterministic
engine. You bring the key; the harness brings the governance.

The one-line pitch: **the model proposes, the ledger disposes.** No
configuration in this document can make the harness store a finding without
evidence — that is enforced by the claim gate below the agent, in code.

## The 60-second path

```bash
pip install 'hunteros-harness[llm]'      # adds LiteLLM
export OPENAI_API_KEY=sk-...             # or ANTHROPIC_API_KEY / OPENROUTER_API_KEY
export HUNTEROS_MODEL=gpt-4o             # no default model is baked in — you pick what you pay for
hunter chat
```

That is the whole setup: the loader reads `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`
/ `OPENROUTER_API_KEY` through LiteLLM's own env resolution when no provider
block is declared, and `HUNTEROS_MODEL` fills the top default model slot.

Prefer a file? `hunter config example` prints a complete, loadable YAML —
copy it to `~/.hunteros/config.yaml` and edit. (The same content ships as
[`examples/config.example.yaml`](../examples/config.example.yaml).)

**No key? Everything still works.** The deterministic engine, the ledger,
the claim gate, `hunter demo`, `hunter scan`, reporting, and the TUI run
with zero credentials and zero network beyond your authorized target.
Evidence-or-nothing does not need a brain — the brain is an accelerator,
the proof obligation is structural.

---

## Configuration reference

Search order (first hit wins):

1. explicit `--config`/path argument
2. `$HUNTEROS_CONFIG`
3. `~/.hunteros/config.yaml`
4. none → pure defaults (deterministic behavior)

Environment overrides **win** over YAML values (except `HUNTEROS_MODEL`,
which is read at call time so you can change it between load and use).

### `model_tiers` — the tier router

One model per tier. The agent loop picks the tier per job: `planner`
(task decomposition), `exploit` (payload/craft work), `verify` (evidence
checking — use a cheap, careful model), `utility` (summarizing, formatting).
Empty or `"auto"` model = inherit: tier's own model → `$HUNTEROS_MODEL` →
planner's model (non-planner tiers inherit the top default).

| Key | Type / default | Meaning |
| --- | -------------- | ------- |
| `provider` | string, default `auto` | Provider name; maps onto LiteLLM's `provider/model` wire prefix (`openai` → `openai/…`, `ollama` → `ollama_chat/…`). `auto` lets LiteLLM infer from the model string. An unknown provider name **with a `base_url`** is treated as OpenAI-compatible. |
| `model` | string, default `""` | Model id; `""` or `auto` inherits (see resolution above). |
| `base_url` | string, default `""` | Override the endpoint (OpenAI-compatible servers, internal gateways). |
| `key_env` | string, default `""` | Env var holding this tier's API key (overrides the provider block). |
| `timeout` | int ≥ 1, default `120` | Seconds per completion. |
| `reasoning_effort` | string, default `""` | `low` / `medium` / `high` for models that support it. |

### `providers` — credentials

| Key | Meaning |
| --- | ------- |
| `key_env` | Env var name holding the key (**preferred** — keys never touch disk). |
| `api_key` | Inline key fallback. `key_env` wins when both are set. |
| `base_url` | Default endpoint for this provider (tiers can override). |

- A provider with **no block at all** → LiteLLM applies its standard env
  resolution (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …).
- A block that declares neither `key_env` nor `api_key` yields no key →
  `auth.missing_key` at use time (exit 4).
- Keyless providers (e.g. Ollama) get **no block** — just set `base_url` on
  the tier.

### `fallback_providers` — the failover chain

Tried in order when the primary fails with a fallback-worthy error (auth,
billing, model-not-found). Each entry: `provider` + `model` (required),
optional `base_url`, `key_env`. Deduped against the primary by
`(provider, model, base_url)`; a link whose declared credential cannot be
resolved is skipped silently — failover must not fail.

### `budget` — the governor

| Key | Default | Meaning |
| --- | ------- | ------- |
| `max_cost_usd` | `5.0` | Hard spend cap. Staged **one-time** warnings at 70% / 85% / 95% ("wind down" advisories), then the run stops. |
| `max_iterations` | `60` | Agent tool-loop turns. |
| `wall_seconds` | `1800.0` | Wall-clock cap (30 min). Set `0` to disable any limit. |

### `agent` — loop settings

| Key | Default | Meaning |
| --- | ------- | ------- |
| `tier` | `basic` | Config vocabulary: `basic` \| `advanced` \| `planner` \| `exploit` \| `verify` \| `utility`. `basic` = no model pinned: deterministic/utility behavior, passive-only capability. Any other value (`advanced` or a model tier) resolves to capability tier **advanced** — active methods and probes authorized within scope. |
| `api_max_retries` | `3` | Attempts per provider (bounded exponential backoff: 1s→8s) before failing over to the next link in the chain. |

### Environment variables

| Variable | Effect |
| -------- | ------ |
| `HUNTEROS_MODEL` | Top default model (read at call time; wins over `model_tiers.*.model` when the tier has none of its own). |
| `HUNTEROS_TIER` | Overrides `agent.tier`. |
| `HUNTEROS_BUDGET_USD` | Overrides `budget.max_cost_usd`. |
| `HUNTEROS_MAX_ITERATIONS` | Overrides `budget.max_iterations`. |
| `HUNTEROS_CONFIG` | Path to the config file (step 2 of the search order). |

Unknown keys, wrong types, and bad tier names are `HunterError`s (exit 8)
whose hint names the exact key — the loader is strict so your config cannot
silently mean nothing.

---

## Worked examples

### OpenAI

```yaml
# ~/.hunteros/config.yaml
model_tiers:
  planner: { provider: openai, model: gpt-4o }
  verify:  { provider: openai, model: gpt-4o-mini }   # cheap, careful
providers:
  openai:
    key_env: OPENAI_API_KEY
agent:
  tier: planner                # basic | planner | exploit | verify | utility
budget:
  max_cost_usd: 10.0
```

```bash
export OPENAI_API_KEY=sk-...
hunter chat
```

### Anthropic

```yaml
model_tiers:
  planner: { provider: anthropic, model: claude-sonnet-4-5 }
  exploit: { provider: anthropic, model: claude-sonnet-4-5 }
  verify:  { provider: anthropic, model: claude-haiku-4-5 }
providers:
  anthropic:
    key_env: ANTHROPIC_API_KEY
agent:
  tier: exploit
```

### OpenRouter (explicit `base_url`) + fallback chain

```yaml
model_tiers:
  planner:
    provider: openrouter
    model: anthropic/claude-sonnet-4.5
    base_url: https://openrouter.ai/api/v1
providers:
  openrouter:
    key_env: OPENROUTER_API_KEY
    base_url: https://openrouter.ai/api/v1
fallback_providers:
  - provider: openai
    model: gpt-4o
    key_env: OPENAI_API_KEY
agent:
  tier: planner
```

Primary dies (rate limit, billing, 404) → the harness retries with backoff,
then dials OpenAI. Any provider reachable through LiteLLM works the same
way (`groq`, `gemini`, `mistral`, `deepseek`, `xai`, …).

### Ollama — local, keyless

```yaml
model_tiers:
  planner:
    provider: ollama            # → ollama_chat/<model> on the wire
    model: llama3
    base_url: http://127.0.0.1:11434
agent:
  tier: planner
```

No `providers` block at all — keyless providers simply don't get one.
Nothing leaves your machine except traffic to the authorized target.

---

## Governance — what the brain can and cannot do

The model's **only** capabilities are the 15 agent tools. It never touches
the ledger, the network, or the filesystem directly; every request passes
the fail-closed scope gate, and every persistence goes through the ledger.

**The LLM CAN:** reason in a private scratchpad (`think` — content never
reaches the ledger), take and read notes, record audit coverage, amend the
run-scoped threat model, send scope-checked HTTP requests, run deterministic
probes, search the ledger, propose findings, and yield to you
(`respond_to_user`) or close the audit (`finish_scan`).

**The LLM CANNOT:** write a finding directly, mark anything verified, touch
evidence rows, widen scope, send a request outside the manifest, or persist
chain-of-thought. Every one of those paths is a structural refusal, not a
prompt request.

### `create_finding_request` — the governance tool (R1–R6)

A finding claim is machine-validated before the ledger ever sees it. Each
rule failure returns a stable `BLOCKED` code the model reads and corrects.

| Rule | Check | BLOCKED code on failure |
| ---- | ----- | ----------------------- |
| **R1** | Required prose present: check_id, title, endpoint, description, impact, severity_justification, counterevidence | `finding.r1_required_fields` |
| **R2** | Every `evidence_ids` entry resolves in this run's ledger **and** its stored sha256 matches a recomputed digest (no invented, guessed, or tampered evidence) | `finding.r2_evidence_missing` / `finding.r2_chain_integrity` |
| **R3** | At least one bound artifact is an `http_exchange` — a self-written note can never carry a finding | `finding.r3_evidence_kind` |
| **R4** | Endpoint is inside the authorized scope (same-origin path, target origin, or manifest host) **and** is the request path of at least one bound `http_exchange` — real evidence for `/search` cannot carry a claim about `/admin` | `scope.target_out_of_scope` / `finding.r4_endpoint_mismatch` |
| **R5** | Dedupe: no existing finding with the same key (findings are immutable in v0.2; the key is case/whitespace-normalized, so `"SQL-ERROR"`/`"/SEARCH"` variants cannot double-report) | `finding.r5_duplicate` |
| **R6** | `severity` ∈ {critical, high, medium, low, info}; `confidence` ∈ {high, medium, low} | `finding.r6_severity_invalid` / `finding.r6_confidence_invalid` |

Even after R1–R6 pass, the storage-layer claim gate (RULE-E1) re-checks the
claim atomically — the model handler never trusts its own validation
(`finding.claim_gate_blocked` is the backstop).

### Debunk replay — "the ledger decides verified"

After the agent loop ends, every remaining CANDIDATE faces a **deterministic**
challenger: the exact check that produced it is re-run independently and its
fresh exchange is bound as replay evidence.

- Signal reproduces → finding promoted to **VERIFIED**.
- Signal gone → **RULED_OUT** (kept forever in the audit trail — RULE-E4).
- Transport error / no replay handler → stays CANDIDATE as
  **needs_follow_up**.

The debunk pass accepts no LLM argument: a model can never talk a finding
into — or out of — the verified state. Verified means "reproduces; anyone
can check", and the ledger, not the brain, is the judge.

### Tier gating — structural, not prompt-shaped

The tool schema list is identical at both tiers; the gates live in the
handlers, so out-of-tier capability is *absent/refused*, not negotiated:

| Action | basic tier | advanced tier | Refusal code |
| ------ | ---------- | ------------- | ------------ |
| `http_request` with GET/HEAD/OPTIONS | allowed | allowed | — |
| `http_request` with POST/PUT/DELETE/… | refused | allowed | `tier.passive_only` |
| `run_probe` passive checks (missing-headers, dir-listing, open-redirect, sensitive-file, method-tamper, idor-heuristic) | allowed | allowed | — |
| `run_probe` active checks (sql-error, path-traversal, unauth-action, auth-bypass, reflected-xss, form-injection) | refused | allowed | `tier.capability_locked` |

### Exit codes (stable contract for scripts)

| Code | Meaning |
| ---- | ------- |
| 0 | ok |
| 1 | generic error |
| 2 | usage error |
| 3 | scope denied |
| 4 | auth / billing |
| 5 | rate limit |
| 6 | claim-gate violation |
| 7 | ledger integrity |
| 8 | config error |
| 130 | interrupted |

Where they fire: exit **7** is `hunter verify` on a tampered ledger; **4/5/8**
are the `HunterError` exit codes the gateway/CLI surface for provider,
rate-limit and config failures; **3** (scope) and **6** (claim gate) are the
`HunterError` layer codes — the CLI maps pre-scan scope refusals to exit 2
(usage), and claim-gate refusals surface as structured
`finding.claim_gate_blocked` / `[BLOCKED]` tool outcomes on the chat and
gateway surfaces.

---

## Troubleshooting

| Symptom | Exit | Fix |
| ------- | ---- | --- |
| `provider.auth` / `auth.missing_key` | 4 | Set the key env var named in the hint; `hunter doctor` reports which providers have keys. Inline `api_key` works but `key_env` is preferred. |
| `provider.billing` | 4 | Top up the provider, or switch via `/model` in chat or `fallback_providers` in config. |
| `provider.rate_limit` (all routes exhausted) | 5 | Slow down, switch model via `/model`, or add a second provider to `fallback_providers`. |
| `config.model_unresolved` | 8 | Set `HUNTEROS_MODEL` or `model_tiers.planner.model`. No default model is baked in — that is deliberate. |
| `config.llm_extra_missing` | 8 | `pip install 'hunteros-harness[llm]'` — LiteLLM is not installed. |
| `provider.context_overflow` | 1 | Compact or shorten the conversation; pick a larger-window model for the planner tier. |
| `config.unknown_key` / `config.type` | 8 | The hint names the exact bad key and expected type — fix the YAML (spaces, not tabs; quote strings with special chars). |

Sanity check any config: `hunter doctor` shows the loaded config path, tier,
resolved planner model, per-provider key status, and the installed LiteLLM
version — yellow notes are opt-in gaps, red FAILs are things that break
`hunter scan`/`hunter chat`.
