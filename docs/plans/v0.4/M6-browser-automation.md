# M6 — Browser Automation (v0.4)

**Goal:** add the smallest useful Playwright capability for client-rendered
surfaces without creating a second network path. Browser actions are available
only inside an explicitly authorized hunt, are fail-closed by the existing
scope gate, produce bounded/redacted evidence, and never expose arbitrary
JavaScript execution.

**Design status:** design-only plan. AUDITOR writes the failing tests in §11
first; BUILDER implements until green. Every acceptance criterion maps to one
planned test. Tests use a deterministic fake Playwright seam; no test starts a
real browser, opens a socket, or downloads Chromium. The M1/M3/M5 contracts
remain the baseline. No test starts a real browser.

---

## 0. Non-goals (M6)

- Browser tools in ordinary chat, gateway, webhook, or TUI conversational
  turns. A browser action is a hunt/network action, not a general chat
  capability.
- Arbitrary JavaScript, `eval`, `page.evaluate`, locator evaluation, script
  injection, or a browser-code tool of any name.
- Screenshots, downloads/uploads, popups, multiple tabs, persistent profiles,
  saved cookies, proxy configuration, or browser extensions.
- Replacing `ScopedHttpClient`, changing `ScopeSet` semantics, or allowing
  browser traffic to bypass the HTTP scope gate.
- Treating a DOM snapshot alone as sufficient proof for a finding. The existing
  claim gate still requires an `http_exchange` artifact for a finding; browser
  artifacts are additional context.
- Automatic Playwright/Chromium installation. The harness never invokes
  `playwright install`, `pip`, a package manager, or a subprocess during a
  hunt or a test.
- Live browser or live external-network tests in CI. Windows CI must remain
  able to run the test suite without a Chromium download.
- A new browser-specific authorization manifest. The existing `ScopeSet` on
  the hunt is the only host authorization source.

---

## 1. Current-state map (what exists, what changes)

| File | Today | M6 change |
| --- | --- | --- |
| `pyproject.toml` | Core dependencies plus `llm`, `telegram`, and `dev` extras; no Playwright extra | Add optional `[browser]` extra containing exactly `playwright>=1.40`; Playwright remains absent from core imports and installs |
| `src/hunter/agent/tools.py` | `build_registry()` assembles 15 basic `ToolSpec`s; handlers use `ToolContext`; `http_request` delegates to `ctx.http` | Add the four browser handlers/specs, built only when browser is enabled **and** Playwright is importable; unavailable browser names return a structured install hint without entering `_specs` |
| `src/hunter/agent/tools_base.py` | `ToolContext` owns run id, ledger, scoped HTTP client, scope, target, emit, config, state; `ToolRegistry` dispatches registered specs and catches tool exceptions | Add an optional run-owned browser session/factory to `ToolContext`; make `ToolRegistry` able to remember unavailable optional tools without advertising them as schemas; add idempotent browser cleanup |
| `src/hunter/agent/browser.py` | — | **New.** Lazy Playwright adapter: headless one-context/one-page session, request/redirect route gate, CSS-selector policy, bounded/redacted outputs, and fake-module seams |
| `src/hunter/agent/loop.py` | Resolves tools from the registry, dispatches handlers, persists declared evidence through `Ledger.add_evidence` | No browser-specific network code; preserve the existing evidence ownership rule. The loop must not close a browser between chat turns because M3 creates a fresh loop for each turn |
| `src/hunter/engine/llm.py` | Builds a `ToolContext` and `AgentLoop` for the ledger-backed LLM engine; closes no browser today | Derive `browser_enabled` from `EngineContext.config` or the configured provider's `agent.browser`; build the conditional registry; put browser cleanup in a `finally` around the whole LLM run/debunk path |
| `src/hunter/workflow/pipeline.py` | Passes an optional config dict to `EngineContext`; owns HTTP client and ledger lifecycle | Keep pipeline ownership unchanged; document/forward the optional browser flag through `config` when a caller supplies it. The pipeline never imports Playwright or downloads a browser |
| `src/hunter/chat/repl.py` | `_audit_open()` creates one run-scoped `ToolContext`; `_audit_finish()` closes HTTP and the ledger; `_audit_turn_result()` creates a new registry/loop per turn | Set `hunt_permission=True` and `browser_enabled` only on the governed audit context; pass the flag to `build_registry`; close the context's browser in `_audit_finish()` before/alongside HTTP cleanup. Normal conversational mode never constructs a `ToolContext` or browser registry |
| `src/hunter/cli/init_wizard.py` | M1 onboarding already stores `agent.browser`; the prompt calls it inert and does not import Playwright | **No behavior change required.** The flag remains writable and loadable when `[browser]` is absent. Any missing-extra message belongs to a browser action, not onboarding |
| `src/hunter/hunt.py`, `src/hunter/cli/main.py` | M3 one-shot hunt resolves scope and calls `run_hunt`/`run_scan`; configured LLM selection already loads provider configuration | Preserve target/scope/permission order. When an LLM hunt is configured with `agent.browser: true`, forward that flag into the engine context; never let it authorize a host or skip the CLI's existing confirmation |
| `src/hunter/tools/scope.py` | `ScopeSet.check_url()` fail-closes missing/unknown schemes and exact unauthorized hosts; `ScopeViolation` is the stable refusal | Reuse this method for initial URLs, current-page URLs, link/form destinations, every Playwright request, and redirect hops. No browser-local host matcher or scope bypass |
| `src/hunter/tools/http_client.py` | `ScopedHttpClient` checks before I/O and does not follow redirects | Leave unchanged. Playwright traffic is governed by the browser route hook plus `ScopeSet.check_url`; it is not smuggled through `httpx` |
| `docs/ROADMAP-v0.3.md` | Browser automation is a P2 item | M6 implementation may update roadmap wording only if the project convention requires it; this plan does not move unrelated roadmap items |
| `README.md`, `docs/FIRST-RUN.md` | M1 browser flag is documented as a later release/inert option | Add a short post-implementation note: install the optional extra and Chromium separately, browser actions are hunt-only and scope-gated; no claim is made that onboarding requires the extra |
| `tests/test_browser_tools.py` | — | **New.** All browser behavior tests, fake Playwright, fake route/page/context, no live browser/network |
| `tests/test_docs_m6.py` | Existing M5 docs static-test pattern reads files directly | **New.** Static pyproject/plan/user-doc contract; no imports of Playwright and no installation |

Existing tests that assert 15 registry tools continue to call
`build_registry("basic")` with browser disabled and remain unchanged. Browser
schemas are additive only when the explicit browser flag and optional package
are both present.

---

## 2. Key decisions (recorded 2026-09-14)

- **K1 — The browser session belongs to `ToolContext`, not `ToolRegistry`.**
  `ToolContext` is the run-scoped object already shared by all chat turns and
  by the LLM engine. M3 rebuilds a registry/loop for every chat turn; putting a
  page in the registry would lose the page between turns. The context stores
  one lazy session and owns its idempotent `close_browser()` operation. The
  registry owns only immutable handler/factory wiring.
- **K2 — Lazy, headless, one session per run.** Playwright is not imported and
  Chromium is not launched while building a registry. The first browser action
  starts `sync_playwright()`, launches `chromium.launch(headless=True)`,
  creates one fresh context and one page, and installs the route guard. The
  session is closed at run end, including the Playwright driver. No persistent
  profile, cookies, storage state, or browser reuse crosses runs.
- **K3 — Two opt-ins are required.** Browser specs are advertised only when
  `browser_enabled=True` (ultimately `agent.browser: true`) **and** the
  Playwright module is importable. A missing extra never makes onboarding or
  non-browser hunts fail. A direct/model request for an unavailable browser
  name receives `browser.unavailable` or `browser.disabled` with an actionable
  hint, while the name remains absent from schemas.
- **K4 — One scope gate, checked twice.** Every explicit navigation URL is
  checked with `ctx.scope.check_url()` before `page.goto`. A fresh Playwright
  context route handler checks every request URL before continuing it; this
  covers redirects and subresource requests. Click/type also check the current
  page URL before acting, inspect an explicit `href`/`action` destination when
  one exists, and re-check the resulting page URL. A blocked request is
  aborted, never continued, and returns a stable scope refusal.
- **K5 — CSS selectors only, no code-bearing selector languages.** The tool
  accepts a bounded selector string but rejects `xpath=`, `text=`, `>>`,
  `javascript:`, `eval(`, braces/control characters, and other explicit
  code/selector-chain forms. It requires exactly one matching element. This is
  a deliberately small selector contract; it is safer than exposing all
  Playwright selector engines and is sufficient for ordinary forms and links.
- **K6 — Browser actions require hunt permission independently of config.**
  A handler requires `ctx.config["hunt_permission"] is True` before it can
  create or use a browser. The governed CLI/agent hunt sets this marker; normal
  chat does not create such a context. `agent.browser` is capability opt-in,
  not operator consent. A browser action is network activity and cannot be
  authorized by a prompt injection or by merely setting a config flag.
- **K7 — DOM events are evidence, not claims.** Browser handlers return
  bounded `browser_event`/`browser_snapshot` artifacts through `ToolOutcome`;
  the loop persists them and the ledger applies its normal redaction/hash
  chain. Browser artifacts alone do not satisfy RULE-E1/R3's required
  `http_exchange` evidence for `create_finding_request`. A model must still
  bind a real scope-gated HTTP exchange to a finding.
- **K8 — Redact before cap, and never return credentials by design.** Snapshot
  text and metadata pass through the existing secret redaction plus browser
  patterns for cookies, authorization, token, API-key, session, and CSRF
  fields before the hard cap. Cookies, headers, local/session storage, typed
  values, and response bodies are never read into tool output. The snapshot
  cap is 12,000 characters; selectors are capped at 512 and typed input at
  4,000. A truncation marker is deterministic.
- **K9 — Missing Playwright is a normal, classified condition.** The install
  hint names both steps: `pip install 'hunteros-harness[browser]'` and
  `python -m playwright install chromium`. The runtime never performs either
  step. If the package is present but Chromium is absent, the same classified
  error is returned when the first action attempts to launch.
- **K10 — Fake Playwright is the only test seam.** `build_registry` accepts a
  `playwright_module` seam (with an explicit `None` meaning unavailable), and
  the context accepts a browser factory/session seam. Fake objects implement
  only the sync methods used by the adapter. Tests monkeypatch no DNS, use no
  localhost server for browser actions, and never import a real Playwright
  browser executable.
- **K11 — M1 remains compatible.** `agent.browser` defaults to `false`, the
  wizard continues to write `true` without the extra, and loading/writing a
  config never imports Playwright. Enabling the flag does not grant browser
  capability outside a governed hunt.

---

## 3. Exact API and seams

### 3.1 Optional dependency and availability

`pyproject.toml` gains exactly:

```toml
[project.optional-dependencies]
browser = ["playwright>=1.40"]
```

The existing `llm`, `telegram`, and `dev` entries remain. There is no
`playwright` entry in core `dependencies`.

New `hunter.agent.browser` helpers:

```python
BROWSER_TOOL_NAMES: tuple[str, ...] = (
    "browser_click",
    "browser_navigate",
    "browser_snapshot",
    "browser_type",
)
MAX_SNAPSHOT_CHARS = 12_000
MAX_SELECTOR_CHARS = 512
MAX_TYPED_CHARS = 4_000
NAVIGATION_TIMEOUT_MS = 15_000
PLAYWRIGHT_INSTALL_HINT = (
    "install browser support with: "
    "pip install 'hunteros-harness[browser]' && "
    "python -m playwright install chromium"
)

def load_playwright() -> Any | None:
    """Return playwright.sync_api or None; never installs or launches."""

def playwright_available(*, module: Any | None = _AUTO) -> bool:
    """Pure availability check for the supplied seam/default import."""
```

The implementation may use a private sentinel for distinguishing the default
loader from an explicit test `None`. It must not use `subprocess`, shell
commands, or a Playwright installer.

### 3.2 Browser session API

The new adapter exposes a deliberately narrow surface. The page/context/
locator objects do not escape the module.

```python
class BrowserUnavailable(RuntimeError): ...

@dataclass(frozen=True)
class BrowserAction:
    action: str
    url: str
    title: str = ""
    snapshot: str = ""
    truncated: bool = False
    text_length: int = 0

class BrowserSession:
    def __init__(
        self,
        scope: ScopeSet,
        *,
        playwright_module: Any | None = None,
        max_snapshot_chars: int = MAX_SNAPSHOT_CHARS,
    ) -> None: ...

    def navigate(self, url: str) -> BrowserAction: ...
    def snapshot(self) -> BrowserAction: ...
    def click(self, selector: str) -> BrowserAction: ...
    def type(self, selector: str, text: str) -> BrowserAction: ...
    def close(self) -> None: ...
```

`close()` is idempotent and closes, in nested `finally` blocks, page/context,
browser, and Playwright driver. A failed close is suppressed after best-effort
cleanup and never replaces the original tool error. The adapter has no public
method that returns `page`, `context`, cookies, headers, storage, or a locator.

The fake module seam must model only:

```text
sync_playwright().start()
  -> chromium.launch(headless=True)
       -> browser.new_context()
            -> context.new_page()
            -> context.route("**/*", route_handler)
```

The adapter may call `page.goto`, `page.url`, `page.title`,
`page.locator(selector)`, locator `count`, `get_attribute`, `fill`, `click`,
and `page.locator("body").inner_text`. It must not call any `evaluate` API.

### 3.3 ToolContext ownership surface

`ToolContext` gets optional, dependency-neutral fields (typing may use
`TYPE_CHECKING`/`Any` so importing `tools_base` does not require Playwright):

```python
@dataclass
class ToolContext:
    # existing fields remain first and unchanged
    ...
    browser_session: Any | None = None
    browser_factory: Callable[[], Any] | None = None

    def ensure_browser(self, factory: Callable[[], Any] | None = None) -> Any:
        """Return the one lazy session; never replace an existing session."""

    def close_browser(self) -> None:
        """Close the run-owned session once; safe when absent/repeated."""
```

`ensure_browser()` uses the injected `browser_factory` first, then the handler
factory supplied by the registry. A production factory constructs
`BrowserSession(ctx.scope, playwright_module=...)`. Tests can inject a fake
session without importing Playwright. The context, not the registry, retains
the resulting object.

### 3.4 Registry API and conditional registration

`build_registry` remains source-compatible for existing callers and gains
keyword-only controls:

```python
def build_registry(
    tier: str = "basic",
    *,
    browser_enabled: bool = False,
    playwright_module: Any = _AUTO,
) -> ToolRegistry: ...
```

Behavior:

1. `browser_enabled=False`: existing 15 specs only; no Playwright import.
   Browser names are remembered as `browser.disabled` only for direct dispatch
   diagnostics and are not in `_specs` or schemas.
2. `browser_enabled=True`, module unavailable: existing 15 specs only; the
   four names are remembered as `browser.unavailable` with the install hint;
   they are not in `_specs` or schemas.
3. `browser_enabled=True`, module available: register exactly four additional
   `ToolSpec`s at `min_tier="basic"`; the registry has 19 specs. Browser
   handlers still require `ctx.config["hunt_permission"] is True`.

`ToolRegistry` adds a private/diagnostic unavailable-name map and a method such
as `register_unavailable(name, code, message)`. `dispatch` checks this map
only after the normal registered-spec lookup. This is not registration and
never changes `schemas_for_tier()`. A direct/model call receives a structured
`ToolOutcome` rather than generic `tool_not_found`, making the missing-extra
case actionable without advertising a capability that cannot run.

### 3.5 Exact browser tool schemas

All four schemas use `additionalProperties: false`; all browser specs have
`min_tier="basic"` because the permission/scope gates are handler-level and
must apply equally to basic and advanced hunts.

```python
browser_navigate = ToolSpec(
    name="browser_navigate",
    description=(
        "Navigate the headless browser to one absolute in-scope http(s) URL. "
        "Redirects and all subrequests are scope-checked; no cookies or headers "
        "are returned."
    ),
    parameters={
        "type": "object",
        "properties": {"url": {"type": "string", "minLength": 1, "maxLength": 2048}},
        "required": ["url"],
        "additionalProperties": False,
    },
    handler=_browser_navigate,
)

browser_snapshot = ToolSpec(
    name="browser_snapshot",
    description=(
        "Return a bounded, redacted visible-text snapshot of the current page. "
        "Cookies, storage, headers, and arbitrary page code are never exposed."
    ),
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
    handler=_browser_snapshot,
)

browser_click = ToolSpec(
    name="browser_click",
    description=(
        "Click exactly one bounded CSS selector on the current in-scope page. "
        "Explicit link/form destinations and resulting redirects are scope-checked."
    ),
    parameters={
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 512},
        },
        "required": ["selector"],
        "additionalProperties": False,
    },
    handler=_browser_click,
)

browser_type = ToolSpec(
    name="browser_type",
    description=(
        "Fill exactly one bounded CSS selector on the current in-scope page. "
        "The typed value is never returned or recorded; resulting requests remain "
        "scope-checked."
    ),
    parameters={
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 512},
            "text": {"type": "string", "maxLength": 4000},
        },
        "required": ["selector", "text"],
        "additionalProperties": False,
    },
    handler=_browser_type,
)
```

The schema text is normative enough for tests to assert names, required fields,
`additionalProperties`, and the absence of an `eval`/script parameter.

---

## 4. Part A — browser adapter safety contract

### 4.1 Session start and route guard

On first action only:

1. Import/use the supplied Playwright module seam. If it is absent, raise the
   classified `BrowserUnavailable` condition with `PLAYWRIGHT_INSTALL_HINT`.
2. Start the sync driver and launch **headless** Chromium. Never pass a user
   profile, storage state, proxy, or downloaded executable path.
3. Create one fresh browser context and one page.
4. Install `context.route("**/*", route_handler)` before navigation. For every
   request, the handler calls `scope.check_url(request.url)` before
   `route.continue_()`. On `ScopeViolation`, it calls `route.abort()` and
   records a blocked reason for the current action. It never rewrites the URL,
   follows it through `httpx`, or calls `allows_host()` as a substitute.
5. A request to an unsupported scheme, missing host, out-of-scope host, or
   malformed URL is aborted. A main-frame redirect that is blocked makes the
   action return `scope.target_out_of_scope`; no out-of-scope URL is exposed in
   the result beyond the existing redacted refusal surface.

The route applies to documents, redirects, scripts, images, XHR/fetch, and
forms. Blocking an optional third-party asset must not silently authorize it;
the action reports a blocked request if it affects the action, and the route
never continues it.

### 4.2 Navigation

`browser_navigate` validates a non-empty absolute URL and calls
`ctx.scope.check_url(url)` before `page.goto`. Relative URLs, `javascript:`,
`data:`, `file:`, `ftp:`, protocol-relative URLs, missing hosts, and malformed
URLs are refused with `scope.target_out_of_scope` (or the stable
`browser.url_invalid` subcode if the implementation distinguishes input
validation). The initial URL is never handed to Playwright before this check.

`page.goto` uses the fixed bounded timeout and `wait_until="domcontentloaded"`.
After it returns, `page.url` is checked again with `ScopeSet.check_url`. The
result contains only a redacted/capped URL and title, plus a next-step hint to
call `browser_snapshot`; it does not include response headers, cookies, or a
raw response body.

### 4.3 Click and type

Before either action:

- Require `ctx.config["hunt_permission"] is True`.
- Require a current page and call `scope.check_url(page.url)`.
- Validate the selector against the CSS-only policy and length cap.
- Resolve exactly one locator; zero or multiple matches return a bounded
  `browser.selector_not_unique` refusal without acting.
- If the element exposes an explicit `href`, `formaction`, or form `action`
  through ordinary locator attributes, resolve it against the current URL with
  `urljoin` and call `scope.check_url` before acting. A `javascript:` value is
  always refused before the click/fill.

`browser_click` calls only the locator's click operation. `browser_type` calls
only the locator's fill operation and records only `text_length`; it never
returns the input or echoes it in a tool message/evidence artifact. After either
action, check `page.url` and let the route hook govern any navigation/request.
A click/type that attempts an out-of-scope redirect returns a blocked outcome;
the route is not allowed to continue the request.

The adapter does not use `page.evaluate`, `locator.evaluate`, `page.add_script`
or equivalent APIs. Website JavaScript may run as part of the target page, but
HunterOS never supplies JavaScript source or executes code in the page.

### 4.4 Snapshot and redaction

`browser_snapshot` reads only visible body text through the supported locator
text API. It does not read cookies, local storage, session storage, headers,
network bodies, or arbitrary DOM properties. The adapter:

1. redacts with `hunter.kernel.redaction.redact_text`;
2. applies browser-local patterns for `cookie`, `set-cookie`, `authorization`,
   `csrf`, `session`, `access_token`, `refresh_token`, `api_key`, and similar
   `name=value` fields;
3. caps the redacted text at `MAX_SNAPSHOT_CHARS` and appends a deterministic
   `...[snapshot truncated]` marker when needed;
4. returns `url`, `title`, `snapshot`, and `truncated` only.

The same sanitizer/cap is applied to titles, URLs, selector-bearing messages,
and scope/error text. The typed value is never passed to the sanitizer for
output because it is never output at all. Ledger redaction remains a second
backstop when the loop persists evidence.

---

## 5. Part B — handlers, permission, and evidence

### 5.1 Handler order

Each browser handler follows this order:

1. **Permission:** if `ctx.config.get("hunt_permission") is not True`, return
   `ToolOutcome(ok=False, blocked=True, code="permission.hunt_required", ...)`.
   Do not import Playwright, create a session, inspect a page, or emit an
   event.
2. **Availability/capability:** a disabled or unavailable registry path returns
   `browser.disabled`/`browser.unavailable` with the install hint. No session
   is created.
3. **Input validation:** bounded URL/selector/text and CSS policy.
4. **Scope preflight:** call the existing scope gate before the browser call.
5. **Action:** use the context-owned session.
6. **Sanitized outcome/evidence:** return bounded data only and emit one
   `engine_event` describing the browser action without secrets.

Tool exceptions are converted by the existing registry safety net, but expected
scope/unavailable/selector conditions should be explicit blocked outcomes with
stable codes so the model can self-correct.

### 5.2 Evidence shapes

The handlers do not write to the ledger. They return artifacts for the existing
`AgentLoop._store_evidence` path:

```python
{
    "kind": "browser_event",
    "data": {
        "action": "navigate" | "snapshot" | "click" | "type",
        "url": "<sanitized current URL>",
        "title": "<sanitized title>",        # when available
        "snapshot": "<sanitized capped text>", # snapshot only
        "truncated": False,                    # snapshot only
        "selector": "<sanitized selector>",   # click/type only
        "text_length": 0,                      # type only; never text
    },
}
```

A blocked action returns no evidence. The loop assigns the evidence id and
appends it to the model-facing tool result exactly as it does for HTTP. The
ledger's deep redaction/hash chain remains authoritative. `browser_event` is
not an `http_exchange`; a browser-only observation cannot pass R3 of
`create_finding_request`.

### 5.3 Registry descriptions and prompt behavior

When Playwright is unavailable and `agent.browser` is true, the governed LLM
context gets a short `config_note` (or the unavailable dispatch result) saying
browser tools are unavailable and naming the install steps. It must not claim
that the browser ran. The hunt itself may continue with the existing HTTP
capabilities; the optional extra is not a prerequisite for onboarding or a
non-browser run.

When the extra is installed but Chromium has not been installed, the first
browser action returns the same normal error with
`python -m playwright install chromium`; no download begins automatically.

---

## 6. Part C — run integration and lifecycle

### 6.1 LLM engine

`LLMEngine.run` computes:

```python
browser_enabled = bool(ctx.config.get("browser_enabled", False))
if "browser_enabled" not in ctx.config:
    provider_config = getattr(self._provider, "config", None)
    browser_enabled = bool(
        getattr(getattr(provider_config, "agent", None), "browser", False)
    )
```

It constructs the `ToolContext` with:

```python
config={
    **ctx.config,
    "tier": self.tier,
    "browser_enabled": browser_enabled,
    "hunt_permission": True,
}
```

It calls `build_registry(self.tier, browser_enabled=browser_enabled)` and wraps
loop execution plus the existing debunk pass in `try/finally`:

```text
create ToolContext
  -> AgentLoop.run (browser session may be lazy-created)
  -> existing debunk pass
finally
  -> tool_ctx.close_browser()
```

No change is made to the finding/claim or deterministic replay path. Browser
artifacts created by the agent are already in the ledger before debunk runs;
the pipeline still owns run closure.

### 6.2 Chat audit

`ChatEngine._audit_open()` adds `browser_enabled` from
`self.config.agent.browser` and `hunt_permission=True` to the existing audit
context. It does not instantiate Playwright. `_audit_turn_result()` passes
`browser_enabled` to `build_registry` on each fresh loop; the context's
existing `browser_session` keeps one page across turns. `_audit_finish()` calls
`ctx.close_browser()` in a `finally` alongside the existing HTTP and ledger
cleanup, including `/audit finish`, one-shot completion, interruption, and
`ChatEngine.close()`.

Normal `_run_conversational()` turns remain provider-only. They never create a
`ToolContext`, never receive browser schemas, and cannot invoke browser tools
merely because the config flag is true. A gateway/webhook has no interactive
hunt permission and therefore cannot invoke browser actions.

### 6.3 CLI/one-shot flow

The existing M3 order remains:

```text
normalize target
  -> resolve/confirm existing scope
     -> choose engine
        -> governed run / LLM context
           -> browser_enabled from agent.browser when configured
              -> browser action only after hunt permission + ScopeSet check
```

`hunter hunt` and `hunter scan` do not add a browser permission prompt or a
second manifest. `--scope`, localhost handling, proposed manifest confirmation,
exit codes, and target checks are unchanged. The explicit CLI invocation is the
operator's hunt permission; the browser tool still checks the context marker
and the host gate.

---

## 7. Existing contracts / builder red lines

1. **Scope is code, not prompt text.** Every browser request goes through
   `ScopeSet.check_url` before it can continue. No browser handler calls a
   lower-level Playwright request method outside the route guard.
2. **Redirects are revalidated.** `page.goto` is not trusted merely because its
   first URL passed. The route handler checks every redirected request and the
   final page URL; an out-of-scope redirect is aborted and blocked.
3. **No arbitrary code execution.** No `evaluate`, script injection, selector
   execution, browser-code tool, or model-controlled Playwright API is added.
4. **Normal chat stays browser-free.** Only governed hunts have
   `hunt_permission`; the optional config flag alone is never permission.
5. **M1 stays usable without `[browser]`.** Config parsing, onboarding, and
   non-browser hunts must work when `importlib.util.find_spec("playwright")`
   returns `None`.
6. **Registry compatibility.** `build_registry("basic")` without keyword
   options remains the existing 15 schemas. Existing tier behavior remains
   handler/registry behavior as pinned by M3 tests; browser tools are basic
   schema entries only when opted in.
7. **Evidence ownership remains in the loop.** Browser handlers return
   artifacts, never call `ledger.add_evidence`, fabricate ids, or create
   findings. `browser_event` cannot bypass the existing HTTP-evidence claim
   gate.
8. **Secrets never enter browser outputs.** No cookie/header/storage API is
   read for output; typed text is not returned or included in evidence; all
   visible text is sanitized and capped before return.
9. **Lifecycle cannot leak.** One context/page per run, close is idempotent,
   and all fatal LLM-run paths close it in `finally`. A second run never sees
   the first run's page or storage.
10. **No hidden installation.** Source has no install subprocess and tests do
    not invoke a real Playwright installer or browser executable.
11. **No live network in new tests.** Fake Playwright receives all calls;
    scope, redirect, redaction, and cleanup behavior are asserted from fake
    objects and in-memory ledger seams.

---

## 8. Data flow (one glance)

```text
M1 onboarding/config
  agent.browser: false|true
          |
          v
CLI hunt or chat /audit (explicit governed hunt permission)
  -> ToolContext {
       ScopeSet,
       hunt_permission=True,
       browser_enabled=<agent.browser>,
       browser_session=None
     }
  -> build_registry(tier, browser_enabled, playwright_module seam)
       |-- disabled/missing package: no browser schemas;
       |                       unavailable dispatch -> install hint
       `-- available: four browser schemas
              |
              v
agent tool call
  -> permission.hunt_required? (before any browser work)
  -> lazy ctx.ensure_browser()
       -> sync_playwright.start()
       -> chromium.launch(headless=True)
       -> fresh context/page + route("**/*")
  -> browser_navigate/click/type
       -> ScopeSet.check_url preflight
       -> route checks every request/redirect before continue
       -> final page URL check
       -> redacted + capped BrowserAction
       -> ToolOutcome(browser_event evidence)
  -> AgentLoop stores evidence (ledger redaction + hash chain)
  -> finding still requires http_exchange evidence
  -> run end / chat audit finish
       -> ctx.close_browser() (page/context/browser/playwright)
```

---

## 9. Error and stable-code table

| Condition | Stable code | Tool behavior |
| --- | --- | --- |
| No governed hunt context | `permission.hunt_required` | Block before import/session/page access |
| Config flag off / browser not opted in | `browser.disabled` | Name absent from schemas; direct call gets enable-browser hint |
| Playwright package absent | `browser.unavailable` | Name absent from schemas; install extra + Chromium hint |
| Chromium executable absent | `browser.unavailable` | First action fails cleanly; no download |
| Initial/final/redirect URL outside scope | `scope.target_out_of_scope` | No initial goto or route continuation; no evidence |
| Unsupported/malformed/javascript URL | `browser.url_invalid` or scope refusal | No Playwright action |
| Selector empty/too long/code-bearing | `browser.selector_invalid` | No locator action |
| Selector matches zero/multiple nodes | `browser.selector_not_unique` | No click/fill action |
| Playwright action/timeout error | `browser.action_error` | Bounded sanitized error; run remains governed and cleanup still occurs |

The implementation may use one stable invalid-URL code rather than the two
input/scope variants, but it must preserve the scope refusal semantics and
never expose a secret-bearing raw URL.

---

## 10. Acceptance criteria

### Pytest-testable behavior — exactly one planned test per criterion

**`tests/test_browser_tools.py`**

- **B1** `build_registry("basic")` remains the existing 15-tool registry and
  does not import or launch Playwright; with `browser_enabled=True` and a fake
  available module it advertises exactly four additional names, sorted schemas
  contain the exact required fields from §3.5, all four are `min_tier="basic"`,
  and the schema has no JavaScript/eval parameter.
- **B2** Browser-disabled registry path is fail-closed: with
  `browser_enabled=False`, no browser name appears in `schemas_for_tier` and a
  direct browser dispatch returns `browser.disabled` without calling the fake
  factory.
- **B3** Missing Playwright is graceful: with `browser_enabled=True` and an
  explicit unavailable-module seam, no browser schema is advertised and a
  direct `browser_navigate` dispatch returns `browser.unavailable` containing
  both `hunteros-harness[browser]` and `playwright install chromium`; no
  subprocess/install hook is called.
- **B4** A context owns one lazy session: two allowed browser actions use one
  fake session, session creation happens only at the first action, repeated
  `close_browser()` calls close page/context/browser/driver once each, and a
  context never shares a session with a second context.
- **B5** Navigation is checked before I/O: an out-of-scope `https://evil.example`
  URL and an unsupported `javascript:alert(1)` URL both return a blocked scope/
  invalid outcome, fake `page.goto` is never called, and no evidence is
  returned.
- **B6** Redirect escape is blocked: a fake route sees an in-scope initial
  request followed by an out-of-scope redirect request; the first continues,
  the second aborts, the action returns `scope.target_out_of_scope`, and no
  out-of-scope request is continued or emitted as evidence.
- **B7** Click target scope is enforced: an in-scope link selector with an
  in-scope `href` may click; a selector whose `href` is an out-of-scope or
  `javascript:` URL is refused before `locator.click`; current-page scope is
  checked for both cases.
- **B8** Type behavior is safe: a unique in-scope input is filled with a
  sentinel secret, the fake receives the exact input, but the `ToolOutcome`,
  browser evidence, event payload, and subsequent model-facing text contain
  neither the sentinel nor any typed value, only `text_length`.
- **B9** Selector injection is refused: `xpath=...`, `text=...`, selector
  chains containing `>>`, `javascript:`, `eval(`, control characters, and
  over-cap selectors perform no locator action; a static source assertion
  confirms the adapter contains no `evaluate(`/script-execution call.
- **B10** Snapshot output is redacted and bounded: a fake body containing cookie,
  bearer/API-key/token/CSRF-shaped values plus text beyond the cap produces no
  secret substring, is at most `MAX_SNAPSHOT_CHARS` plus the deterministic
  marker, sets `truncated=True`, and does not call cookies/storage/header APIs.
- **B11** Browser evidence follows the loop contract: an allowed fake navigate
  and snapshot return `browser_event` artifacts with sanitized/capped data,
  while a blocked action returns no artifact; the real in-memory ledger only
  receives evidence when the existing loop storage seam is invoked, and a
  browser artifact alone is not treated as `http_exchange` evidence.
- **B12** Permission is independent of the flag: a registry with browser
  enabled and a fake available module, but a context lacking
  `config["hunt_permission"]`, returns `permission.hunt_required` for each
  browser action and never creates a browser session.
- **B13** Browser cleanup survives a run exception: an LLM-engine run whose
  fake provider raises after a browser session was created still calls the
  context/session close path exactly once, and the original classified error
  remains the surfaced failure rather than a cleanup exception.
- **B14** Browser flag wiring is hunt-only: a governed audit context with
  `agent.browser=true` passes `browser_enabled=True` to `build_registry` and
  can receive browser schemas; the same config used by a normal chat turn
  creates no browser context/tools and never calls the browser factory.

**`tests/test_docs_m6.py`**

- **B15** Packaging/static contract: `tomllib` finds exactly the `[browser]`
  extra with `playwright>=1.40`, core dependencies do not contain Playwright,
  the plan names the two explicit install commands, and the plan/source
  contract states that tests do not download Chromium or run an installer.
- **B16** User-facing contract: `README.md` and/or `docs/FIRST-RUN.md` explain
  browser automation is optional, hunt-only, scope-gated, and requires the
  separate Chromium install; the existing M1 `agent.browser` onboarding flag
  remains mentioned as usable without the extra.

Every B criterion maps to exactly one test function in the named file; a test
may use parametrization for the cases explicitly listed inside its one
criterion, but no criterion is split across tests.

---

## 11. Adversarial matrix (risk → design answer → where tested)

| # | Risk | Design answer | Test |
| --- | --- | --- | --- |
| 1 | Model navigates to an unauthorized host | Initial URL calls `ScopeSet.check_url` before Playwright; no socket/page navigation occurs | B5 |
| 2 | In-scope page redirects to an unauthorized host | Route hook checks every request, aborts the redirect, and final URL is checked | B6 |
| 3 | `javascript:`, `data:`, `file:`, or malformed URL hides code in a navigation | Existing scope gate rejects non-http(s); explicit browser URL validation is before goto | B5 |
| 4 | Link/form action escapes scope | Current page and explicit `href`/`formaction`/`action` are checked before click/fill; route remains the backstop | B7 |
| 5 | Selector language becomes code execution | CSS-only bounded selectors; reject XPath/text chains, JavaScript/eval markers, controls; no evaluate API | B9 |
| 6 | Typed password/API key leaks through tool result or evidence | Type result omits value; evidence stores only length; ledger redaction remains backstop | B8 |
| 7 | Cookie, bearer, CSRF, API key appears in DOM snapshot | Browser-specific redaction runs over the complete snapshot before cap; cookies/storage are never read | B10 |
| 8 | Huge DOM floods model/ledger | Redacted snapshot has a hard 12,000-character cap and deterministic truncation marker | B10 |
| 9 | Missing optional package crashes onboarding or an entire non-browser hunt | Conditional registry, no eager import, structured unavailable install hint | B3, B15 |
| 10 | Chromium is silently downloaded in Windows CI | No installer/subprocess path; fake-only tests and static contract prohibit downloads | B3, B15 |
| 11 | Browser session leaks after provider/tool failure | Context owns one session; LLM engine and audit finish close in finally/idempotent path | B4, B13 |
| 12 | Browser flag is mistaken for operator consent | Separate `hunt_permission` marker is required before any browser operation | B12 |
| 13 | Normal chat invokes browser tools | Normal chat never creates a ToolContext/registry and has no hunt permission | B14 |
| 14 | Browser evidence bypasses finding claim gate | Browser artifacts use `browser_event`, never `http_exchange`; handlers never create findings or evidence ids | B11 |
| 15 | Optional dependency import changes existing registry/test behavior | Default build remains 15 tools and never imports Playwright; conditional path is keyword-only | B1, B2 |
| 16 | Cross-run state/cookies leak | Fresh context per ToolContext/run; no persistent profile/storage state; close destroys it | B4 |
| 17 | A blocked third-party asset is treated as authorized because the main URL passed | Route pattern covers all requests, not only document navigation; blocked requests never continue | B6 |
| 18 | Cleanup error masks the actual browser/provider failure | Cleanup is best-effort and idempotent in `finally`; original classified error wins | B13 |

---

## 12. Test plan (auditor implements verbatim)

| File | Test name | Asserts |
| --- | --- | --- |
| `tests/test_browser_tools.py` | `test_registry_adds_exact_browser_tools_only_when_available` | B1 |
| `tests/test_browser_tools.py` | `test_browser_disabled_path_has_no_schema_and_no_factory_call` | B2 |
| `tests/test_browser_tools.py` | `test_missing_playwright_is_graceful_without_install_or_download` | B3 |
| `tests/test_browser_tools.py` | `test_tool_context_owns_one_lazy_session_and_idempotent_cleanup` | B4 |
| `tests/test_browser_tools.py` | `test_navigation_scope_and_scheme_checked_before_page_goto` | B5 |
| `tests/test_browser_tools.py` | `test_redirect_route_escape_is_aborted_and_blocked` | B6 |
| `tests/test_browser_tools.py` | `test_click_preflights_href_and_current_page_scope` | B7 |
| `tests/test_browser_tools.py` | `test_type_never_echoes_or_records_typed_secret` | B8 |
| `tests/test_browser_tools.py` | `test_selector_injection_is_refused_and_no_evaluate_exists` | B9 |
| `tests/test_browser_tools.py` | `test_snapshot_redacts_secrets_and_caps_output` | B10 |
| `tests/test_browser_tools.py` | `test_browser_events_use_loop_evidence_contract` | B11 |
| `tests/test_browser_tools.py` | `test_browser_actions_require_hunt_permission` | B12 |
| `tests/test_browser_tools.py` | `test_llm_run_closes_browser_when_provider_raises` | B13 |
| `tests/test_browser_tools.py` | `test_browser_flag_wires_only_governed_hunt_context` | B14 |
| `tests/test_docs_m6.py` | `test_browser_extra_is_optional_and_no_download_contract_is_documented` | B15 |
| `tests/test_docs_m6.py` | `test_user_docs_describe_optional_hunt_only_browser` | B16 |

### Fake Playwright contract

`tests/test_browser_tools.py` defines in-memory fakes for driver, browser,
context, page, route, request, locator, and provider. The fakes record method
calls and expose counters for `start`, `launch`, `new_context`, `new_page`,
`route`, `goto`, `click`, `fill`, `abort`, `continue_`, and cleanup. They never
open a socket and never import `playwright`.

The redirect test invokes the captured route handler directly with fake
requests. The snapshot test supplies secrets and oversized text directly from a
fake `body.inner_text()`. The run-exception test injects the fake provider and
browser factory at the existing `LLMEngine`/`EngineContext` seams. The chat
wiring test uses the existing fake provider and string-capturable chat setup;
it does not use REPL stdin or a live provider.

All new tests use `tmp_path` for any ledger/config state, clear
`HUNTER_STATE_DIR`/`HUNTEROS_CONFIG` when invoking CLI/chat surfaces, and
restore any registry/browser seam in `finally`/`monkeypatch`. There is no
Chromium fixture and no `pytest-playwright` dependency.

---

## 13. Verify commands (Windows dev reality + CI)

```bash
# New tests first; all fake Playwright, no browser executable required
.venv/Scripts/python -m pytest tests/test_browser_tools.py tests/test_docs_m6.py -q

# Existing safety and agent contracts nearby
.venv/Scripts/python -m pytest tests/test_agent_tools.py tests/test_agent_loop.py \
  tests/test_adversarial.py tests/test_adversarial_v02.py -q

# Full suite and lint
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m ruff check src tests
```

Optional manual smoke testing is explicitly outside CI and must be run only by
an authorized operator after installing both pieces:

```bash
.venv/Scripts/python -m pip install -e ".[browser]"
.venv/Scripts/python -m playwright install chromium
```

The implementation must not run either command itself and never invokes `playwright install`
during a hunt or test. Windows CI runs the normal dependency matrix with no
Playwright/Chromium download step. A future
manual browser smoke test must be a separately opt-in workflow, never part of
pytest.

---

## 14. Builder order (suggested)

1. **Packaging/static contract:** add the `[browser]` extra declaration and
   the optional-install/user-doc plan markers; write B15/B16 first. Confirm
   importing config/onboarding and `build_registry("basic")` does not import
   Playwright.
2. **Context/session seams:** add the dependency-neutral `ToolContext` fields,
   `ensure_browser`, `close_browser`, and `src/hunter/agent/browser.py` fake
   seam. Implement lazy lifecycle, route gate, URL checks, selector policy,
   redaction/caps, and B3–B6/B9–B10 tests.
3. **Registry and handlers:** add unavailable diagnostics, conditional four
   specs, exact schemas, permission gate, browser evidence, and B1/B2/B7/B8/
   B11/B12 tests. Run the existing 15-tool registry tests before integration.
4. **LLM lifecycle integration:** pass `browser_enabled` from provider/context,
   set `hunt_permission` only for governed runs, preserve M1 flag behavior,
   and add the `finally` cleanup. Land B4/B13/B14 and rerun agent/ledger tests.
5. **Chat/CLI surfaces:** wire the existing audit context and one-shot config
   without changing M3 scope/confirmation behavior; confirm normal chat has no
   browser path. Keep all browser output behind the existing AgentLoop evidence
   seam.
6. **Documentation and final audit:** update README/FIRST-RUN only after real
   optional-install wording is verified; run all B tests, the full 759-pass
   baseline plus new tests, Ruff, and inspect the Windows CI job for any
   accidental browser download step.
