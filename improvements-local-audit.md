# improvements.md — local audit (target lokal, hunt lokal)

> **Status: OPEN (2026-11-01).** Local-directory audit exists in the CLI but
> is not reachable through the daemon, and the mechanism it uses (mount the
> directory on a loopback HTTP server) is the wrong tool for source review.
> This file records exactly what works, what does not, and the four changes
> that would make local audit real.

---

## 1. What already works

`hunter hunt <dir>` accepts a local directory. `hunt.py:normalize_hunt_target`
returns `(absolute_path, "dir")` for an existing directory, and
`cli/main.py:313` mounts it with `mount_local_dir` — a `ThreadingHTTPServer`
bound to `127.0.0.1:0`, serving the directory for the duration of the run,
with `localhost_scope()` applied automatically.

That is genuinely useful for one class of target: **a locally running web
app** (a build output, a staging bundle, a practice target served from disk).
The audit then exercises the same HTTP surface it would exercise remotely.

## 2. What does not work

### 2.1 The daemon accepts a local target and then cannot run it

`daemon.py:_validate_hunt_task` calls `normalize_hunt_target(target)` and
requires `normalized == target`:

```python
normalized, kind = normalize_hunt_target(target)
if kind == "invalid" or normalized != target:
    raise ValueError(f"invalid hunt target: {target!r}")
```

For an **already-absolute** directory path this check passes — verified:
`normalize_hunt_target("/home/simon/relay-settlement/smart-contracts/contracts")`
returns `("/home/simon/relay-settlement/smart-contracts/contracts", "dir")`,
so `normalized == target` is True and `_validate_hunt_task` **accepts** the
task. (A relative path would be rejected, because `normalize_hunt_target`
resolves it — so the failure is silent and path-shape-dependent.)

The task then reaches `hunt_worker` → `run_hunt(target, scope=...)` →
`run_scan(target, ...)`, all of which expect a **URL**. `daemon.py` contains
no reference to `mount_local_dir` at all (verified: the string appears in
`cli/main.py`, never in `daemon.py`). So a directory task is queued
successfully, claimed, and then fails inside the pipeline with a target that
is a filesystem path.

Net effect: local audit is CLI-only, single-shot, and cannot be queued,
scheduled, or fed by a feeder. The 24/7 engine cannot audit anything local —
and it fails in a way that looks like a pipeline error rather than "this
target kind is not supported here."

### 2.2 Mounting source code as HTTP is the wrong mechanism

`mount_local_dir` exists to serve a web app. Pointing it at a **source
tree** (e.g. `relay-settlement/smart-contracts/contracts`) produces:

- Deterministic probes look for HTTP response headers, cookie flags, open
  redirects, and SQL error strings. None of those exist in a `.sol` file.
- The LLM agent's only read tool is `http_request`. It can `GET
  /RelayHub.sol` and receive the source as a response body, but every tool
  it has is shaped for an HTTP surface, not for static analysis.
- The claim gate requires at least one real `http_exchange` as evidence. For
  a Solidity bug the correct evidence is a **code location** (file, line,
  the vulnerable statement), not an HTTP exchange. So a genuine static
  finding either cannot pass the gate, or passes it by attaching a
  meaningless exchange as evidence — which is worse than refusing.

That last point is not a bug to fix quietly. The gate's evidence contract is
what makes findings trustworthy; widening it to accept "I read a file" would
let any model assertion become a finding. The right answer is a **separate
evidence kind for code locations**, validated by re-reading the file and
re-hashing it — the same discipline the gate already applies to HTTP
exchanges, pointed at a different substrate.

### 2.3 No scope story for local targets

`localhost_scope()` is a fixed allowlist of loopback hosts. It is correct for
a mounted directory, but it means every local audit shares one scope, and a
feeder cannot express "audit this directory, not that one." The scope
manifest format (`{"hosts": [...], "allow_subdomains": bool}`) has no concept
of a filesystem path at all.

## 3. Proposed changes

### 3.1 A `local` target kind that survives the daemon

`normalize_hunt_target` already returns `kind == "dir"`. The daemon should
honour it instead of fighting it:

- `_validate_hunt_task` accepts `kind == "dir"` and requires the path to
  exist and be a directory **at claim time**, not at enqueue time (the
  directory may be created later by a checkout step).
- `hunt_worker` detects a directory task and wraps the run in
  `mount_local_dir`, exactly as `cli/main.py:313` does — one mount per task,
  torn down in a `finally`.
- The task payload gains an optional `"local_root"` key recording the
  directory that was mounted, so the report and the retro can say what was
  audited instead of showing an ephemeral `127.0.0.1:PORT` URL that no
  longer means anything.

### 3.2 A `code_location` evidence kind

Add a second evidence substrate beside `http_exchange`:

- `kind: "code_location"` with `{path, line_start, line_end, sha256}`.
- Validation re-reads the file at the recorded path, re-hashes the recorded
  span, and refuses on mismatch — the same tamper-evidence discipline the
  gate already applies to exchanges.
- The claim gate's minimum-evidence rule becomes: **at least one
  `http_exchange` OR at least one `code_location`**, never neither, and
  never a self-written note.
- A finding whose only evidence is a `code_location` can reach
  `theoretical` and `in-code`, but **not** `verified` — `verified` stays
  reserved for deterministic replay, which for a code finding means an
  executed PoC (`hunt poc run`), not a reading.

This keeps the ladder honest: a code reading is real evidence, but it is not
proof of exploitability, and the ladder already has a rung for exactly that
distinction.

### 3.3 Path-scoped local audit

Extend the scope manifest with an optional `local_roots` list:

```json
{
  "name": "relay-contracts-review",
  "hosts": [],
  "local_roots": ["/home/operator/relay-settlement/smart-contracts/contracts"]
}
```

A local task is authorized when its mounted root is inside one of
`local_roots`. Absent the key, local targets fall back to today's
`localhost_scope()` behaviour, so nothing existing breaks.

### 3.4 A review engine, not an HTTP engine

The `llm` engine drives an agent loop whose tools are HTTP-shaped. Local
source review needs its own driver behind the same `EngineDriver` seam:

- `engine: "review"` — reads files under the mounted root, one at a time,
  and emits `code_location` evidence.
- Deterministic checks that make sense on source: presence of `ReentrancyGuard`
  on state-changing external functions, `onlyOwner`-style modifiers on fund
  paths, unchecked `delegatecall`, uninitialized storage pointers, missing
  zero-address validation on constructors.
- The engine changes; the evidence contract does not. That is the whole
  point of the `EngineDriver` seam, and it is currently unused for anything
  but HTTP.

## 4. What this deliberately does not do

- **It does not turn the LLM into an oracle.** A `code_location` is evidence
  that a span of code exists and matches its hash. It is not evidence that
  the span is vulnerable. The model still has to argue that, and the
  argument is still falsifiable.
- **It does not weaken `verified`.** Only an executed PoC promotes a finding
  to `verified`, in every mode.
- **It does not auto-scan the filesystem.** A local root must be named in a
  scope manifest. The fail-closed default stays fail-closed.

## 5. Verified current behaviour

- `hunter hunt <dir>` mounts the directory on loopback and runs — confirmed
  by reading `cli/main.py:313` and `hunt.py:mount_local_dir`.
- `normalize_hunt_target("/home/simon/relay-settlement/smart-contracts/contracts")`
  returns `(".../contracts", "dir")` with `normalized == target` True, so
  `daemon._validate_hunt_task` **accepts** the task (verified by direct call).
- `daemon.py` contains no reference to `mount_local_dir` (verified: the
  string appears in `cli/main.py`, never in `daemon.py`), so the accepted
  task fails downstream in `run_scan`, which expects a URL.
- A *relative* directory path is rejected by `_validate_hunt_task`, because
  `normalize_hunt_target` resolves it and the equality check then fails — so
  the same directory is accepted or rejected depending on how it is spelled.
- `localhost_scope()` is the only local scope, and it is host-based, not
  path-based.
