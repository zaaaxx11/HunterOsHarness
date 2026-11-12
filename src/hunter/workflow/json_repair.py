"""Repair a tool call whose `arguments` arrived as truncated JSON.

Providers that reason mid-call emit partial JSON ("{\"findings\": ") and
json.loads chokes. A strict parse throws away real findings; a lenient
one recovers every complete object inside the fragment.

Unit-tested below against real provider-shaped fragments.
"""
import json
import re
from typing import Any


def repair_json_fragment(raw: str) -> Any:
    """Best-effort parse of a possibly-truncated JSON arguments string.

    Strategy: complete open containers with the missing closers, then parse;
    if that fails, extract every balanced {...} object and take the first
    one that parses. Returns {} when nothing is recoverable.
    """
    s = (raw or "").strip()
    if not s:
        return {}

    # 1) already valid. A literal ``null``/``true``/``123`` is valid JSON but is
    # NOT a usable argument object, and returning it verbatim makes callers
    # unable to tell "parsed null" from "nothing recoverable" — so non-container
    # scalars normalise to {} (the documented failure value).
    try:
        parsed = json.loads(s)
        if isinstance(parsed, (dict, list)):
            return parsed
        return {}
    except Exception:
        pass

    # 2) close the open containers
    stack = []
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]":
            if stack:
                stack.pop()
    # drop a dangling key/value that has no value yet ("..., \"x\":")
    tail = s.rstrip().rstrip(",")
    for opener in (":", ","):
        if tail.endswith(opener):
            tail = tail[: -len(opener)].rstrip().rstrip(",")
            # a key without a value must be dropped entirely
            if tail.endswith('"'):
                idx = tail.rfind('"', 0, len(tail) - 1)
                if idx != -1 and tail[idx - 1: idx] in (":", "{", ",") or True:
                    # find the last key start
                    kstart = tail.rfind('"', 0, idx)
                    if kstart != -1:
                        tail = tail[:kstart].rstrip().rstrip(",")
            break
    if in_str:
        tail += '"'
    closer = "".join(reversed(stack))
    for candidate in (tail + closer, tail):
        try:
            return json.loads(candidate)
        except Exception:
            continue

    # 3) pull complete objects out of the fragment
    objs = _balanced_objects(s)
    for o in objs:
        try:
            return json.loads(o)
        except Exception:
            continue
    # 4) arrays of objects — return the first object found
    if objs:
        try:
            return json.loads(objs[0])
        except Exception:
            pass
    return {}


def _balanced_objects(s: str) -> list[str]:
    """Return every top-level {...} substring in s, ignoring string content."""
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth:
                depth -= 1
                if depth == 0 and start is not None:
                    out.append(s[start:i + 1])
                    start = None
    return out


# ---------------- self-test ------------------------------------------------
if __name__ == "__main__":
    CASES = [
        # (fragment, expected_to_parse, expected_keys_or_None)
        ('{"findings": ', False, None),                 # unrecoverable: no data yet
        ('{"findings": [{"title": "a", "severity": "high"}', True, None),
        ('{"findings": [{"title": "x", ', True, None),       # trailing comma
        ('{"findings": [{"title": "ok"}]}', True, None),     # complete
        ('{"a": 1}', True, None),
        ('{"a": ', False, None),                                # unrecoverable
        ('', False, None),
        ('not json at all', False, None),
        ('{"weird": "unterminated string', True, None),      # in_str + stack
        ('[{"title": "t1"}, {"title": "t2"}, {"title": "t', True, None),
    ]
    bad = []
    for frag, should_parse, _ in CASES:
        try:
            r = repair_json_fragment(frag)
            ok = isinstance(r, (dict, list)) and r != {}
        except Exception:
            ok = False
        status = "PARSED" if ok else "EMPTY "
        if ok != should_parse:
            bad.append(f"{frag!r} -> {status} (expected {'parse' if should_parse else 'empty'})")
        else:
            print(f"  ✓ {frag[:48]!r:52} -> {r if r else '{}'}")

    # the real regression: findings must survive
    r = repair_json_fragment('{"findings": [{"title": "SQLi in login", "severity": "high"}')
    if isinstance(r, dict) and r.get("findings"):
        f = r["findings"][0]
        assert f.get("title") == "SQLi in login", f
        assert f.get("severity") == "high", f
        print("\n✅ REGRESSION OK: real finding title+severity recovered from truncated args")
    else:
        bad.append("regression: finding not recovered")

    if bad:
        print("\nFAILURES:")
        for b in bad:
            print("  ✗", b)
        raise SystemExit(1)
    print("\nALL CLEAN")
