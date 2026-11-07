"""PoC handling — deterministic exploit plans plus safe local-fork execution.

Two hard rules:

1. :func:`generate_poc_plan` is a TEMPLATE, not an LLM call and not a guess:
   the same finding always yields byte-identical text.  The template is keyed
   by the vulnerability class (reentrancy / access-control / oracle /
   overflow / arbitrary-call / generic), read from the finding's explicit class
   fields first and its title as the fallback.

2. :func:`run_poc` only ever shells out to ``forge test`` inside a LOCAL
   workdir.  Before the shell is touched the PoC source is scanned for a
   non-local RPC endpoint and REFUSED if one is present — PoCs run against a
   local fork (anvil / a local archive node), never against a remote host.

``run_poc`` returns exactly ``{"ok": bool, "output": str, "exit_code": int}``.
It never raises for an expected failure: a missing PoC, a missing ``forge``, a
remote endpoint, a timeout and a compile error all come back as data.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

__all__ = [
    "VULN_TYPES",
    "generate_poc_plan",
    "run_poc",
    "vuln_type",
]

#: Canonical vuln-type keys a plan can be keyed on.
VULN_TYPES: tuple[str, ...] = (
    "reentrancy",
    "access-control",
    "oracle",
    "overflow",
    "arbitrary-call",
    "generic",
)

#: Ordered keyword sets — the FIRST class that matches wins.
_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("reentrancy", ("reentran", "re-entran", "callback", "cei", "checks-effects")),
    ("oracle", ("oracle", "price-feed", "price feed", "twap", "manipulat",
                "spot-price", "spot price", "flash-loan", "flashloan",
                "liquidation", "exchange-rate")),
    ("access-control", ("access control", "access-control", "authoriz", "authoris",
                        "owner", "onlyowner", "privilege", "auth", "role",
                        "permission", "unprotected", "missing-check", "unauthenticated",
                        "idor", "initializ")),
    ("overflow", ("overflow", "underflow", "arithmetic", "truncat", "cast",
                  "precision", "rounding", "wrap", "unchecked")),
    ("arbitrary-call", ("delegatecall", "arbitrary-call", "arbitrary call",
                        "unchecked-call", "unchecked call", "call-injection",
                        "rce", "code-execution", "code execution", "command-injection",
                        "deserializ", "template-injection", "ssti", "ssrf")),
)

_EXPLICIT_KEYS = ("vuln_type", "vuln_class", "klass", "category", "type", "bug_class", "kind")

#: Hosts that are unambiguously local.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"})

_URL_RE = re.compile(r"\b(?P<scheme>https?|wss?|ftp)://(?P<host>[^\s\"'/?#]+)", re.IGNORECASE)

_MAX_OUTPUT_CHARS = 20_000

_SAFETY_NOTE = (
    "SAFETY: run this ONLY against a local fork (e.g. `anvil --fork-url "
    "<local archive node>` or `anvil` with a local state dump). Never point a PoC "
    "at a remote host; the harness refuses PoCs that name one."
)


# --------------------------------------------------------------------------- #
# plan generation
# --------------------------------------------------------------------------- #
def vuln_type(finding: dict) -> str:
    """Classify a finding into one of :data:`VULN_TYPES` (deterministic)."""
    if not isinstance(finding, dict):
        return "generic"
    explicit = " ".join(str(finding.get(k) or "") for k in _EXPLICIT_KEYS).lower()
    if explicit.strip():
        hit = _match(explicit)
        if hit != "generic":
            return hit
    title = str(finding.get("title") or "").lower()
    if title.strip():
        hit = _match(title)
        if hit != "generic":
            return hit
    if not explicit.strip():
        # Last resort: the description.  Only used when the finding has no
        # explicit class field AND no informative title.
        hit = _match(str(finding.get("description") or "").lower())
        if hit != "generic":
            return hit
    return "generic"


def _match(text: str) -> str:
    for name, words in _KEYWORDS:
        if any(word in text for word in words):
            return name
    return "generic"


def _location_line(finding: dict) -> str:
    ev = finding.get("evidence")
    fpath = line = None
    if isinstance(ev, dict):
        fpath = ev.get("file") or ev.get("path")
        line = ev.get("line") or ev.get("start_line")
    if not fpath:
        fpath = finding.get("file") or finding.get("path")
    if line is None:
        line = finding.get("line")
    if not fpath and isinstance(ev, str):
        fpath = ev
    if not fpath:
        return "location: (unstated — the verifier rejects findings without file:line)"
    return f"location: {fpath}" + (f":{line}" if line is not None else "")


def generate_poc_plan(finding: dict) -> str:
    """A deterministic exploit-test sketch for ``finding``.

    Same input -> identical output (no clocks, no randomness, no LLM).
    """
    finding = finding if isinstance(finding, dict) else {}
    kind = vuln_type(finding)
    title = str(finding.get("title") or "(untitled finding)").strip()
    severity = str(finding.get("severity") or "unknown").strip().lower()
    desc = " ".join(str(finding.get("description") or "").split())
    if len(desc) > 600:
        desc = desc[:597] + "..."
    ev = finding.get("evidence")
    ev_str = "" if ev is None else str(ev).strip()
    if len(ev_str) > 400:
        ev_str = ev_str[:397] + "..."

    body = _TEMPLATES[kind]
    parts = [
        f"# PoC plan — {title}",
        "",
        f"- vuln class: {kind}",
        f"- severity: {severity}",
        f"- {_location_line(finding)}",
        f"- finding id: {finding.get('id') or '(unassigned)'}",
        f"- verifier status: {finding.get('status') or '(unverified)'}",
        "",
        "## Hypothesis",
        desc or "(the verifier recorded no description)",
    ]
    if ev_str:
        parts += ["", "## Evidence on record", "```", ev_str, "```"]
    parts += body(title=title, severity=severity)
    parts += [
        "",
        "## How to run",
        "```",
        "forge test --match-path test/Exploit.t.sol -vvv",
        "```",
        "",
        "## Safety",
        _SAFETY_NOTE,
        "",
    ]
    return "\n".join(parts)


# Templates are functions of (title, severity) so the output is stable and the
# text never has to be assembled by string surgery on shared fragments.
_TEMPLATES: dict[str, Any] = {
    "reentrancy": lambda *, title, severity: [
        "",
        "## Preconditions",
        "1. `Target` holds value or accounting state that a single call path mutates.",
        "2. `Target` writes its state AFTER the external call (CEI violated), or the",
        "   guard is per-function rather than global.",
        "3. The attacker can supply the callee: an ERC777/ERC721/ERC1155 receiver hook,",
        "   a `call{value:}` recipient, or any user-registered callback.",
        "",
        "## Attack sequence",
        "1. Deploy the attacker contract and fund it with the minimum `deposit()` amount.",
        "2. Have the attacker call `Target.withdraw()` (or the redeem path).",
        "3. In `receive()`/`onERC777Received`, re-enter `withdraw()` before the first",
        "   call finishes zeroing the attacker's balance.",
        "4. Repeat until `Target`'s balance is drained or the accounting falls below",
        "   the invariants the protocol assumes.",
        "",
        "## Test skeleton (forge, local fork only)",
        "```solidity",
        "// test/Exploit.t.sol",
        "pragma solidity ^0.8.0;",
        "",
        f"contract ReentrancyExploitTest  // {title}",
        "    Target internal target;",
        "    uint256 internal constant DEPOSIT = 1 ether;",
        "",
        "    function setUp() public {",
        "        target = new Target();          // or an existing fork deployment",
        "        vm.deal(address(this), DEPOSIT);",
        "        vm.deal(address(target), 10 ether);",
        "    }",
        "",
        "    function test_reentrancy_drains_target() public {",
        "        uint256 before = address(target).balance;",
        "        target.deposit{value: DEPOSIT}();",
        "        target.withdraw();              // re-enters from receive()",
        "        assertLt(address(target).balance, before, \"target was drained\");",
        "        assertGt(address(this).balance, DEPOSIT, \"attacker profited\");",
        "    }",
        "",
        "    receive() external payable {",
        "        if (address(target).balance >= DEPOSIT) {",
        "            target.withdraw();          // the re-entrant call",
        "        }",
        "    }",
        "}",
        "```",
        "",
        "## Success criteria",
        "- `address(this).balance > DEPOSIT` after a single transaction — value left the",
        "  protocol and landed with the attacker.",
        "- The target's accounting is inconsistent with its token balance",
        "  (`target.totalAccounted() != token.balanceOf(address(target))`).",
        "- Reverting the re-entrant call makes the test fail, proving causality",
        "  (remove `receive()` and re-run — the exploit must stop working).",
        "",
        "## Falsifier",
        "If a mutex/nonReentrant guard, or a CEI ordering, makes the second call",
        "revert, the finding is refuted — record that outcome rather than weakening",
        "the test.",
    ],
    "access-control": lambda *, title, severity: [
        "",
        "## Preconditions",
        "1. A privileged function mutates value, ownership, or configuration.",
        "2. The guard is absent, wrong (`tx.origin`, `require(msg.sender != 0)`), or",
        "   incomplete (a missing `onlyOwner` on one of several entry points).",
        "3. The attacker address is a plain EOA with no special role.",
        "",
        "## Attack sequence",
        "1. Deploy a fresh attacker EOA: `address attacker = address(0xBAD);`",
        "2. Impersonate it: `vm.prank(attacker);` (or `vm.startPrank` for a chain).",
        "3. Call the privileged entry point directly with attacker-controlled arguments.",
        "4. Assert the state change happened, and that it should not have.",
        "",
        "## Test skeleton (forge, local fork only)",
        "```solidity",
        "// test/Exploit.t.sol",
        "pragma solidity ^0.8.0;",
        "",
        f"contract AccessControlExploitTest  // {title}",
        "    Target internal target;",
        "    address internal attacker = address(0xBAD);",
        "",
        "    function setUp() public {",
        "        target = new Target();",
        "        assertTrue(target.owner() != attacker, \"attacker must start unprivileged\");",
        "    }",
        "",
        "    function test_unprivileged_caller_can_escalate() public {",
        "        address previousOwner = target.owner();",
        "        vm.prank(attacker);",
        "        target.setOwner(attacker);        // <- the privileged entry point",
        "        assertEq(target.owner(), attacker, \"takeover succeeded\");",
        "        assertTrue(target.owner() != previousOwner);",
        "    }",
        "",
        "    // Control: the same call must REVERT for an honest guard.",
        "    function test_control_guard_reverts_for_stranger() public {",
        "        vm.prank(attacker);",
        "        vm.expectRevert();",
        "        target.setOwner(attacker);",
        "    }",
        "}",
        "```",
        "",
        "## Success criteria",
        "- The privileged state change lands while `msg.sender == attacker`.",
        "- The attacker address held no role before the call (asserted in `setUp`).",
        "- The control test proves the same call reverts under a correct guard —",
        "  otherwise the test proves nothing about access control.",
        "",
        "## Falsifier",
        "An `onlyOwner`/role check that makes the attacker call revert refutes the",
        "finding.  Fixing the test to use the owner address would be fabrication.",
    ],
    "oracle": lambda *, title, severity: [
        "",
        "## Preconditions",
        "1. A value-affecting path reads a price: `getPrice()`, `latestAnswer()`,",
        "   `getReserves()` used directly as a spot price, or a manipulable TWAP window.",
        "2. That price feeds collateral checks, mint/redeem ratios, or liquidations.",
        "3. The manipulator can move the price within one transaction.",
        "",
        "## Attack sequence",
        "1. Snapshot the honest price `p0`.",
        "2. Manipulate the source (swap into the pool / write the mock feed) so the",
        "   reported price becomes `p1` with `p1 != p0`.",
        "3. In the SAME transaction, exercise the value path that trusts the price",
        "   (borrow, mint, redeem, liquidate).",
        "4. Restore the price and measure the profit left behind.",
        "",
        "## Test skeleton (forge, local fork only)",
        "```solidity",
        "// test/Exploit.t.sol",
        "pragma solidity ^0.8.0;",
        "",
        f"contract OracleExploitTest  // {title}",
        "    Target internal target;",
        "    MockFeed internal feed;",
        "",
        "    function setUp() public {",
        "        feed = new MockFeed();",
        "        feed.setPrice(1_000e18);          // honest price p0",
        "        target = new Target(address(feed));",
        "    }",
        "",
        "    function test_price_manipulation_mints_free_value() public {",
        "        uint256 honestMint = target.previewMint(1 ether);",
        "        feed.setPrice(1e18);              // p1: 1000x lower",
        "        uint256 manipulatedMint = target.previewMint(1 ether);",
        "        assertGt(manipulatedMint, honestMint * 100, \"price was trusted blindly\");",
        "",
        "        feed.setPrice(1_000e18);          // restore before anyone notices",
        "        assertGt(target.balanceOf(address(this)), 0, \"value was extracted\");",
        "    }",
        "}",
        "```",
        "",
        "## Success criteria",
        "- Value extracted within one transaction using a price the attacker moved.",
        "- The same path is safe when the price source cannot be moved in-transaction",
        "  (control test with a stale/TWAP feed that is not manipulable).",
        "- The profit is denominated: the attacker's starting and ending balances are",
        "  both asserted, so a rounding artifact cannot masquerade as an exploit.",
        "",
        "## Falsifier",
        "A TWAP with a window longer than one block, a sanity-bounded feed, or a",
        "circuit breaker that rejects the manipulated price refutes the finding.",
    ],
    "overflow": lambda *, title, severity: [
        "",
        "## Preconditions",
        "1. Arithmetic runs in an `unchecked` block, or a narrowing cast drops high",
        "   bits (`uint256 -> uint128`, `int -> uint`).",
        "2. A user controls at least one operand (amount, shares, timestamp, index).",
        "3. The result feeds accounting, a bound check, or a share/asset conversion.",
        "",
        "## Attack sequence",
        "1. Establish a baseline call with small, honest values.",
        "2. Drive one operand to the value that wraps or truncates: `type(uint256).max`,",
        "   `2**128`, `0`, or a one-unit-different value that crosses the boundary.",
        "3. Assert the stored/credited amount contradicts the input (wrap or truncation).",
        "4. Assert the effect is monetisable (shares > assets deposited, or a bound",
        "   check bypassed).",
        "",
        "## Test skeleton (forge, local fork only)",
        "```solidity",
        "// test/Exploit.t.sol",
        "pragma solidity ^0.8.0;",
        "",
        f"contract OverflowExploitTest  // {title}",
        "    Target internal target;",
        "",
        "    function setUp() public {",
        "        target = new Target();",
        "    }",
        "",
        "    function test_boundary_value_wraps_or_truncates() public {",
        "        uint256 big = type(uint256).max;",
        "        uint256 credited = target.deposit(big);      // unchecked math inside",
        "        assertLt(credited, big, \"value wrapped instead of reverting\");",
        "        assertEq(target.totalDeposits(), credited, \"accounting followed the wrap\");",
        "    }",
        "",
        "    function test_control_honest_value_is_correct() public {",
        "        uint256 credited = target.deposit(1 ether);",
        "        assertEq(credited, 1 ether, \"honest path must stay exact\");",
        "    }",
        "}",
        "```",
        "",
        "## Success criteria",
        "- A stored value differs from the mathematically correct result for a reachable",
        "  input (checked with `assertEq` against the expected number, not just `<`).",
        "- The honest path stays exact, so the defect is the boundary, not the model.",
        "",
        "## Falsifier",
        "Solidity 0.8 checked arithmetic (or an explicit bound) reverting on the",
        "boundary input refutes the finding — record the revert.",
    ],
    "arbitrary-call": lambda *, title, severity: [
        "",
        "## Preconditions",
        "1. A user-controlled target address and/or calldata reaches a low-level",
        "   `call`, `delegatecall`, or an interpreter/sink (`exec`, `eval`, a template",
        "   engine, a deserializer, a shell).",
        "2. The caller passes little or no allow-list check.",
        "3. The execution happens with the contract's (or process's) privileges.",
        "",
        "## Attack sequence",
        "1. Deploy a malicious callee that records being called and what it could do",
        "   with the caller's authority.",
        "2. Reach the sink with attacker-controlled target + calldata from an",
        "   unprivileged account.",
        "3. Assert the attacker's code ran (state it mutated, or a token it received).",
        "4. Escalate exactly one step: from \"it ran\" to \"it ran with privilege\".",
        "",
        "## Test skeleton (forge, local fork only)",
        "```solidity",
        "// test/Exploit.t.sol",
        "pragma solidity ^0.8.0;",
        "",
        f"contract ArbitraryCallExploitTest  // {title}",
        "    Target internal target;",
        "    Attacker internal attackerCode;",
        "    address internal attacker = address(0xBAD);",
        "",
        "    function setUp() public {",
        "        target = new Target();",
        "        attackerCode = new Attacker();",
        "        token.mint(address(target), 100 ether);   // value at risk",
        "    }",
        "",
        "    function test_attacker_steers_the_call() public {",
        "        bytes memory data = abi.encodeWithSignature(",
        "            \"transfer(address,uint256)\", attacker, 100 ether);",
        "        vm.prank(attacker);",
        "        target.execute(address(token), 0, data);   // <- unchecked sink",
        "        assertEq(token.balanceOf(attacker), 100 ether, \"funds left the target\");",
        "    }",
        "}",
        "```",
        "",
        "## Success criteria",
        "- The attacker's data executed with the target's privileges: a token transfer,",
        "  a storage write to a protected slot, or a process spawned by the service.",
        "- Prove the escalation, not merely the call: `balanceOf(attacker)` rises, or a",
        "  slot the attacker could not write directly has changed.",
        "",
        "## Falsifier",
        "A target allow-list, a selector filter, or a privilege drop before the call",
        "refutes it.  \"The function accepts an address\" alone proves nothing.",
    ],
    "generic": lambda *, title, severity: [
        "",
        "## Preconditions",
        "1. Re-read the cited code at the recorded file:line and state the exact",
        "   assumption the finding claims is violated.",
        "2. Identify the actor (unprivileged caller, attacker contract, malformed input)",
        "   and the state that must hold before the attack.",
        "",
        "## Attack sequence",
        "1. Build the minimal fixture that puts the system in the required state.",
        "2. Perform the single action the finding describes.",
        "3. Observe the effect: a value transfer, a state divergence, or an",
        "   authorization that should not have been granted.",
        "4. Reduce to the smallest failing example before drawing conclusions.",
        "",
        "## Test skeleton (forge, local fork only)",
        "```solidity",
        "// test/Exploit.t.sol",
        "pragma solidity ^0.8.0;",
        "",
        f"contract ExploitTest  // {title}",
        "    function setUp() public {",
        "        // deploy/attach the target, fund the attacker, snapshot state",
        "    }",
        "",
        "    function test_impact_is_real() public {",
        "        // 1. record the pre-state",
        "        // 2. perform the action",
        "        // 3. assert the IMPACT, not the mechanism",
        "        //    (a balance moved, a stored value changed, an invariant broke)",
        "    }",
        "}",
        "```",
        "",
        "## Success criteria",
        "- The assertion fails on the pre-fix code and passes after the fix.",
        "- The asserted quantity is an impact (money, privilege, invariant), never",
        "  \"the function was called\".",
        "",
        "## Falsifier",
        "If no reachable input produces the effect, the claim is theoretical — record",
        "the refutation and lower the finding's status instead of keeping the claim.",
    ],
}


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
def run_poc(
    poc_path: str | Path,
    workdir: str | Path,
    *,
    timeout: float = 600.0,
    forge_bin: str | None = None,
) -> dict:
    """Run ``forge test --match-path <poc_path>`` in ``workdir``.

    Returns ``{"ok": bool, "output": str, "exit_code": int}``.  Local workdirs
    only: a PoC that names a non-local RPC endpoint is refused before the shell
    is touched, and a missing ``forge`` returns a clear 127 result.
    """
    workdir = Path(workdir)
    poc = Path(poc_path)
    if not poc.is_absolute():
        poc = workdir / poc

    if not poc.is_file():
        return _result(False, f"PoC not found: {poc}", -1)

    remote = _remote_endpoints(poc)
    if remote:
        return _result(
            False,
            "refused: PoC references a non-local endpoint ("
            + ", ".join(sorted(remote))
            + ") — PoCs must run against a local fork only. Rewrite it to use "
            "anvil / 127.0.0.1 before running.",
            126,
        )

    forge = forge_bin or shutil.which("forge")
    if not forge:
        return _result(
            False,
            "forge not found: install Foundry "
            "(https://book.getfoundry.sh/getting-started/installation) and put "
            "`forge` on PATH, or pass forge_bin=<path>.",
            127,
        )

    match = _match_path_arg(poc, workdir)
    cmd = [forge, "test", "--match-path", match]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return _result(False, f"forge test timed out after {timeout:g}s", 124)
    except FileNotFoundError:
        return _result(False, f"forge not found at {forge!r}", 127)
    except OSError as exc:
        return _result(False, f"failed to run forge: {exc}", 126)

    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if len(output) > _MAX_OUTPUT_CHARS:
        output = output[:_MAX_OUTPUT_CHARS] + "\n… [output truncated]"
    return _result(proc.returncode == 0, output, int(proc.returncode))


def _result(ok: bool, output: str, exit_code: int) -> dict:
    return {"ok": bool(ok), "output": str(output), "exit_code": int(exit_code)}


def _match_path_arg(poc: Path, workdir: Path) -> str:
    """``--match-path`` wants a path relative to the forge root when possible."""
    try:
        return poc.relative_to(workdir).as_posix()
    except ValueError:
        return str(poc)


def _remote_endpoints(poc: Path) -> set[str]:
    """Non-local URL endpoints named on a non-comment line of the PoC."""
    try:
        text = poc.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    found: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//") or line.startswith("*") or line.startswith("/*"):
            continue
        for m in _URL_RE.finditer(line):
            scheme = m.group("scheme").lower()
            host = m.group("host").strip().lower()
            host_no_port = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            if host in _LOCAL_HOSTS or host_no_port in _LOCAL_HOSTS:
                continue
            found.add(f"{scheme}://{host}")
    return found