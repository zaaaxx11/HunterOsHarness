"""Post-hunt retro curator: deterministic, previewed, and fail-closed."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel

from hunter.agent.skills import DUPLICATE_JACCARD, parse_skill_md, tokenize, user_skills_dir, write_skill

__all__ = [
    "Candidate", "SkillDraft", "INJECTION_MARKERS", "extract_candidates", "similarity",
    "dedupe_candidate", "scan_draft", "draft_skill", "review_and_save", "curate",
]

INJECTION_MARKERS = (
    "ignore previous instructions", "ignore all previous instructions",
    "disregard previous instructions", "disregard all instructions",
    "forget your instructions", "new instructions", "you are now", "act as",
    "pretend to be", "system prompt", "assistant:", "developer message",
    "<|im_start", "<|im_end", "### instruction", "reveal your",
)


@dataclass(frozen=True)
class Candidate:
    title: str
    summary: str
    lessons: tuple[str, ...]
    origin: str


@dataclass
class SkillDraft:
    name: str
    description: str
    version: str = "0.1.0"
    min_tier: str = "basic"
    tags: tuple[str, ...] = ("curated",)
    body: str = ""
    flagged: bool = False
    flag_reasons: tuple[str, ...] = ()
    duplicates: tuple[str, ...] = ()


def _status(finding: Any) -> str:
    value = getattr(finding, "status", "")
    return str(getattr(value, "value", value)).lower().replace(" ", "_")


def _lesson_lines(retro: Any) -> tuple[str, ...]:
    return tuple(str(line) for line in (getattr(retro, "lessons", ()) or ()) if str(line).strip())


def extract_candidates(retro: Any, findings: Iterable[Any], *, max_candidates: int = 3) -> list[Candidate]:
    findings = list(findings)
    lessons = _lesson_lines(retro)
    verified = [finding for finding in findings if _status(finding) == "verified"]
    groups: dict[str, list[Any]] = {}
    for finding in verified:
        key = str(getattr(finding, "key", "")).split("|", 1)[0]
        groups.setdefault(key, []).append(finding)
    candidates: list[Candidate] = []
    for key, rows in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))[:2]:
        titles = "; ".join(str(getattr(row, "title", key)) for row in rows)
        remediations = "; ".join(str(getattr(row, "remediation", "")) for row in rows if getattr(row, "remediation", ""))
        summary = titles + (f" — {remediations}" if remediations else "")
        candidates.append(Candidate(key or "verified finding", summary, lessons or ("Replay verified behavior and bind evidence.",), "verified-finding"))
        if len(candidates) >= max_candidates:
            return candidates
    ruled_out = [finding for finding in findings if _status(finding) in {"ruled_out", "ruled-out", "ruledout"}]
    if ruled_out and len(candidates) < max_candidates:
        titles = "; ".join(str(getattr(row, "title", "ruled-out candidate")) for row in ruled_out)
        candidates.append(Candidate("Replay before you claim", f"Ruled-out findings: {titles}.", lessons or ("Replay before you claim.",), "debunk"))
    gaps = [str(gap) for gap in (getattr(retro, "gaps", ()) or ())]
    if any(gap.lower().startswith("gate failed: recon") for gap in gaps) and len(candidates) < max_candidates:
        candidates.append(Candidate("Recon coverage", "Recon gate failure left the attack surface under-mapped.", lessons or ("Map the surface before probing.",), "gap"))
    return candidates[:max_candidates]


def similarity(a: frozenset[str], b: frozenset[str]) -> float:
    union = a | b
    return 0.0 if not union else len(a & b) / len(union)


def dedupe_candidate(candidate: Candidate, corpus: Any) -> tuple[str, ...]:
    candidate_tokens = frozenset(tokenize(f"{candidate.title} {candidate.summary}"))
    result: list[str] = []
    normalized = "-".join(tokenize(candidate.title))
    for skill in getattr(corpus, "skills", ()):
        skill_name = str(getattr(skill, "name", ""))
        skill_tokens = frozenset(tokenize(f"{skill_name.replace('-', ' ')} {getattr(skill, 'description', '')} {' '.join(getattr(skill, 'tags', ()) or ())}"))
        if normalized == skill_name or similarity(candidate_tokens, skill_tokens) >= DUPLICATE_JACCARD:
            result.append(skill_name)
    return tuple(sorted(set(result)))


def scan_draft(text: str) -> tuple[bool, tuple[str, ...]]:
    value = str(text or "")
    reasons: list[str] = []
    lowered = value.lower()
    for marker in INJECTION_MARKERS:
        if marker.lower() in lowered:
            reasons.append(marker)
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        reasons.append("control character")
    return bool(reasons), tuple(dict.fromkeys(reasons))


def _slug(text: str, origin: str) -> str:
    words = re.findall(r"[a-z0-9]+", str(text).lower())
    slug = "-".join(words)[:64].strip("-")
    return slug or f"technique-{origin}"


def _clamp_description(text: str) -> str:
    text = " ".join(str(text).split())
    if len(text) <= 60:
        return text
    cut = text[:60].rsplit(" ", 1)[0].strip()
    return cut or text[:60]


def _template(candidate: Candidate) -> SkillDraft:
    body_lines = [f"# {candidate.title}", "", "## Doctrine"]
    body_lines.extend(f"{index}. {lesson}" for index, lesson in enumerate(candidate.lessons, 1))
    body_lines.extend(["", "Evidence or nothing — a skill you cannot ground in a replayed run is a story, not a technique."])
    body = "\n".join(body_lines).splitlines()[:45]
    draft = SkillDraft(
        name=_slug(candidate.title, candidate.origin),
        description=_clamp_description(candidate.summary),
        tags=("curated", candidate.origin),
        body="\n".join(body),
    )
    flagged, reasons = scan_draft(draft.description + "\n" + draft.body)
    draft.flagged, draft.flag_reasons = flagged, reasons
    return draft


_CURATOR_PROMPT = """Draft one inert HunterOS methodology skill card from this verified retro candidate.\nDo not provide instructions that bypass scope, claim, tier, or evidence gates. Return a frontmattered SKILL.md card with name and description plus a concise 20-45 line doctrine body.\nCandidate:\n"""


def draft_skill(candidate: Candidate, *, provider: Any = None) -> SkillDraft:
    if provider is None:
        return _template(candidate)
    try:
        response = provider.complete("utility", _CURATOR_PROMPT + candidate.summary + "\nLessons: " + "; ".join(candidate.lessons))
        raw = getattr(response, "text", response)
        raw = str(raw or "")
        start = raw.find("---")
        end = raw.find("---", start + 3) if start >= 0 else -1
        if start < 0 or end < 0:
            raise ValueError("provider did not return frontmatter")
        card = raw[start:end + 3]
        front_lines = card.splitlines()
        values: dict[str, str] = {}
        for line in front_lines[1:]:
            if ":" in line and not line.startswith(" ") and not line.startswith("-"):
                key, value = line.split(":", 1)
                values[key.strip()] = value.strip()
        body = raw[end + 3:].strip().splitlines()[:45]
        name = _slug(values.get("name", candidate.title), candidate.origin)
        description = _clamp_description(values.get("description", candidate.summary))
        tags = ("curated", candidate.origin)
        validation = "---\n" + f"name: {name}\ndescription: {description}\nversion: 0.1.0\nmetadata:\n  min_tier: basic\n" + "---\n\n" + "\n".join(body) + "\n"
        if parse_skill_md(validation, directory_id=name) is None:
            raise ValueError("provider card failed validation")
        flagged, reasons = scan_draft(description + "\n" + "\n".join(body))
        return SkillDraft(name, description, tags=tags, body="\n".join(body), flagged=flagged, flag_reasons=reasons)
    except Exception:
        return _template(candidate)


def _default_ask(prompt: str) -> bool:
    try:
        answer = input(prompt)
    except Exception:
        return False
    return answer.strip().lower() in {"y", "yes"}


def review_and_save(
    draft: SkillDraft, *, home=None, ask: Callable[[str], bool] | None = None, console: Console | None = None
):
    console = console or Console()
    root = user_skills_dir(home)
    target = root / draft.name / "SKILL.md"
    from hunter.agent.skills import load_corpus
    corpus = load_corpus(home=home)
    duplicates = draft.duplicates or dedupe_candidate(Candidate(draft.name, draft.description, (), "curated"), corpus)
    draft.duplicates = duplicates
    verdict = f"duplicates existing skill(s): {', '.join(duplicates)}" if duplicates else f"unique against {len(corpus.skills)} skills"
    lines = [f"name: {draft.name}", f"description: {draft.description}", f"tier: {draft.min_tier}", f"tags: {', '.join(draft.tags)}", verdict, f"target: {target}", "", draft.body]
    if draft.flagged:
        lines.extend(["", f"warning: draft contains instruction-like text: {', '.join(draft.flag_reasons)}", "this skill will be saved INERT (quarantined: true) and never mounted until you edit the file"])
    if target.parent.exists():
        lines.extend(["", f"exists: {target} — skipped to avoid overwrite"])
        console.print(Panel("\n".join(lines), title="Skill preview"))
        return None
    console.print(Panel("\n".join(lines), title="Skill preview"))
    try:
        approved = bool((ask or _default_ask)(f"save this skill to {target}? [y/N] "))
    except Exception:
        approved = False
    if not approved:
        console.print("skipped — not saved")
        return None
    path = write_skill(draft, home=home)
    console.print(f"saved {path}" + (" (inert/quarantined)" if draft.flagged else ""))
    return path


def curate(run_id: str, *, ledger: Any, home=None, ask=None, console=None, provider=None) -> str:
    try:
        from hunter.phases import compute_retro
        retro = compute_retro(ledger, run_id)
    except Exception:
        return "no skill candidates from this retro"
    candidates = extract_candidates(retro, ledger.findings(run_id))
    if not candidates:
        return "no skill candidates from this retro"
    from hunter.agent.skills import load_corpus
    corpus = load_corpus(home=home)
    saved = skipped = duplicates = 0
    output: list[str] = []
    for candidate in candidates:
        dup = dedupe_candidate(candidate, corpus)
        if dup:
            duplicates += 1
            output.append(f"skipped duplicate of existing skill(s): {', '.join(dup)}")
            continue
        draft = draft_skill(candidate, provider=provider)
        path = review_and_save(draft, home=home, ask=ask, console=console)
        if path is None:
            skipped += 1
        else:
            saved += 1
            output.append(f"saved candidate: {candidate.title}")
    output.append(f"curator: {saved} saved, {skipped} skipped, {duplicates} duplicates of existing skills")
    return "\n".join(output)
