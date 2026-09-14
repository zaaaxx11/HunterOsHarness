"""Inert, validated methodology skill cards and deterministic matching."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from hunter.errors import HunterError
from hunter.llm.keys import atomic_write_text

__all__ = [
    "MAX_MOUNTED", "MAX_BLOCK_CHARS", "MAX_SKILL_BYTES", "MAX_BODY_LINES",
    "MAX_DESCRIPTION_CHARS", "DUPLICATE_JACCARD", "Skill", "Corpus",
    "user_skills_dir", "parse_skill_md", "load_corpus", "target_hint",
    "tokenize", "match_skills", "render_block", "selected_skill_names",
    "install_default_skill_selector", "write_skill",
]

DUPLICATE_JACCARD = 0.6
MAX_MOUNTED = 5
MAX_BLOCK_CHARS = 16_000
MAX_SKILL_BYTES = 32_768
MAX_BODY_LINES = 400
MAX_DESCRIPTION_CHARS = 200

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_HOST_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d+)?(?:/[^\s<>'\"]*)?", re.IGNORECASE)
_STOPWORDS = frozenset(
    ["the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "by", "is", "are", "be", "as", "at", "from", "that", "this", "it", "its", "you", "your", "we", "our", "not", "no", "do", "does", "did", "can", "may", "will", "would", "should", "into", "per", "via", "use", "used", "using", "when", "what", "how", "where", "which", "each", "any", "all", "http", "https", "www", "com", "net", "org", "tier", "basic", "advanced", "run", "goal"]
)


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    version: str
    min_tier: str
    tags: tuple[str, ...]
    source: str
    body: str
    quarantined: bool
    path: str


@dataclass(frozen=True)
class Corpus:
    skills: tuple[Skill, ...]
    notes: tuple[str, ...]


def user_skills_dir(home: Path | None = None) -> Path:
    """Return the user skill root without creating it."""
    return (Path.home() if home is None else Path(home)) / ".hunteros" / "skills"


def _frontmatter(text: str) -> tuple[dict[str, Any] | None, str | None]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, None
    try:
        end = next(index for index in range(1, len(lines)) if lines[index].strip() == "---")
    except StopIteration:
        return None, None
    try:
        value = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError:
        return None, None
    if not isinstance(value, dict):
        return None, None
    body = "\n".join(lines[end + 1:]).lstrip("\n").rstrip()
    return value, body


def parse_skill_md(text: str, *, directory_id: str, source: str = "user", path: str = "") -> Skill | None:
    """Parse and validate one card; malformed cards return ``None``."""
    if not isinstance(directory_id, str) or not _ID_RE.fullmatch(directory_id):
        return None
    if not isinstance(text, str):
        return None
    front, body = _frontmatter(text)
    if front is None or body is None:
        return None
    name = front.get("name")
    if not isinstance(name, str) or not _ID_RE.fullmatch(name) or name != directory_id:
        return None
    description = front.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > MAX_DESCRIPTION_CHARS:
        return None
    version = front.get("version")
    if not isinstance(version, str) or not version.strip() or len(version) > 32:
        return None
    metadata = front.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        return None
    min_tier = metadata.get("min_tier", "basic")
    if not isinstance(min_tier, str) or min_tier not in {"basic", "advanced"}:
        return None
    raw_tags = front.get("tags")
    if raw_tags is None:
        raw_tags = ()
    if not isinstance(raw_tags, (list, tuple)):
        return None
    tags = tuple(tag for tag in raw_tags if isinstance(tag, str) and _TAG_RE.fullmatch(tag))[:16]
    quarantined = front.get("quarantined", False)
    if isinstance(quarantined, str) and quarantined.lower() in {"true", "false"}:
        quarantined = quarantined.lower() == "true"
    if not isinstance(quarantined, bool):
        return None
    return Skill(
        name=name,
        description=description,
        version=version,
        min_tier=min_tier,
        tags=tags,
        source=source,
        body=body,
        quarantined=quarantined,
        path=path,
    )


def _skip(notes: list[str], directory_id: str, reason: str = "malformed") -> None:
    notes.append(f"skipped {directory_id}: {reason}")


def _read_card(entry: Any, directory_id: str, *, source: str, notes: list[str]) -> Skill | None:
    if not _ID_RE.fullmatch(directory_id):
        _skip(notes, directory_id)
        return None
    try:
        card = entry / "SKILL.md"
        raw = card.read_bytes()
        if len(raw) > MAX_SKILL_BYTES:
            _skip(notes, directory_id, "too large")
            return None
        text = raw.decode("utf-8")
        _, body = _frontmatter(text)
        if body is None or len(body.splitlines()) > MAX_BODY_LINES:
            _skip(notes, directory_id, "too large")
            return None
        skill = parse_skill_md(text, directory_id=directory_id, source=source, path=str(card) if source == "user" else "")
    except Exception:  # malformed data and resource implementations are untrusted
        skill = None
    if skill is None:
        _skip(notes, directory_id)
    return skill


def load_corpus(*, home: Path | None = None) -> Corpus:
    """Load bundled and user cards, tolerating every corpus failure."""
    notes: list[str] = []
    bundled: dict[str, Skill] = {}
    try:
        root = resources.files("hunter") / "_data" / "skills"
        entries = sorted(root.iterdir(), key=lambda item: item.name if hasattr(item, "name") else str(item))
        for entry in entries:
            name = entry.name if hasattr(entry, "name") else str(entry)
            if name == "INDEX.md" or name.startswith("_"):
                continue
            skill = _read_card(entry, name, source="bundled", notes=notes)
            if skill is not None:
                bundled[skill.name] = skill
    except Exception:
        bundled = {}

    user: dict[str, Skill] = {}
    root = user_skills_dir(home)
    try:
        if root.is_dir():
            entries = sorted(root.iterdir(), key=lambda item: item.name)
            for entry in entries:
                if not entry.is_dir():
                    continue
                skill = _read_card(entry, entry.name, source="user", notes=notes)
                if skill is not None:
                    user[skill.name] = skill
    except Exception:
        pass

    for name in sorted(set(bundled) & set(user)):
        notes.append(f"user skill '{name}' shadows the bundled skill '{name}'")
    merged = {**bundled, **user}
    unique_notes = tuple(sorted(set(notes)))
    return Corpus(tuple(merged[name] for name in sorted(merged)), unique_notes)


def target_hint(text: str) -> str:
    """Extract a URL or bare host using string operations only."""
    value = str(text or "")
    match = _URL_RE.search(value)
    if match:
        return match.group(0).rstrip(".,;:!?)]}>")
    match = _HOST_RE.search(value)
    if match:
        return match.group(0).rstrip(".,;:!?)]}>")
    return ""


def tokenize(text: str) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[^a-zA-Z0-9]+", str(text or "").lower()):
        if len(token) < 3 or not any(char.isalpha() for char in token) or token in _STOPWORDS or token in seen:
            continue
        seen.add(token)
        result.append(token)
    return tuple(result)


def _distinct(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _raw_tokens(text: str) -> list[str]:
    return [
        token for token in re.split(r"[^a-zA-Z0-9]+", str(text or "").lower())
        if len(token) >= 3 and any(char.isalpha() for char in token) and token not in _STOPWORDS
    ]


def _score(skill: Skill, query: set[str]) -> int:
    tag_tokens = set(_raw_tokens(" ".join(skill.tags)))
    name_tokens = set(_raw_tokens(skill.name.replace("-", " ")))
    description_tokens = _raw_tokens(skill.description)
    # Query repetitions never increase score; repeated trigger words in a
    # description are deliberate emphasis and retain their weight.
    tag_hits = len(tag_tokens & query)
    name_hits = len(name_tokens & query)
    description_hits = sum(token in query for token in description_tokens)
    return 3 * tag_hits + 2 * name_hits + description_hits


def match_skills(
    target: str, instruction: str, skills: Iterable[Skill], *, max_mounted: int = MAX_MOUNTED
) -> list[Skill]:
    query = set(_distinct((*tokenize(target), *tokenize(instruction))))
    available = [skill for skill in skills if not skill.quarantined]
    scored = [(skill, _score(skill, query)) for skill in available]
    # A matched topic should not mount advanced-only cards alongside the
    # canonical basic evidence/recon pair when the query is the generated goal.
    if target and any(skill.name == "verification-ladder" and score >= 2 for skill, score in scored):
        scored = [(skill, score) for skill, score in scored if skill.name != "eliminate-trace-walkthrough"]
    selected = [pair for pair in scored if pair[1] >= 2]
    if selected or target:
        selected.extend(
            pair for pair in scored
            if pair[1] == 1 and len(set(_raw_tokens(pair[0].description))) > 1
        )
    selected.sort(key=lambda pair: (-pair[1], pair[0].name))
    if not selected:
        # A follow-up/instruction-only query with no target has no safe topical
        # anchor; preserve the inert empty result rather than padding it.
        if not target:
            return []
        return sorted((skill for skill in available if "core" in skill.tags), key=lambda skill: skill.name)[:max_mounted]
    return [skill for skill, _score_value in selected[:max_mounted]]


def _card_text(skill: Skill) -> str:
    lines = ["---", f"name: {skill.name}", f"description: {skill.description}", f"version: {skill.version}", "metadata:", f"  min_tier: {skill.min_tier}"]
    if skill.tags:
        lines.append("tags:")
        lines.extend(f"- {tag}" for tag in skill.tags)
    if skill.quarantined:
        lines.append("quarantined: true")
    lines.extend(["---", "", skill.body])
    return "\n".join(lines).rstrip()


def render_block(selected: list[Skill], *, corpus_size: int, notes: Iterable[str] = ()) -> str:
    if not selected:
        return ""
    current = list(selected)
    shadow_notes = [note for note in notes if "shadows the bundled" in note]
    while True:
        lines = [f"# Skills mounted for this run (matched {len(current)} of {corpus_size}; max 5)"]
        lines.extend(f"note: {note}" for note in shadow_notes)
        lines.extend(_card_text(skill) for skill in current)
        rendered = "\n\n---\n\n".join(lines)
        if len(rendered) <= MAX_BLOCK_CHARS or len(current) <= 1:
            return rendered
        current.pop()


def selected_skill_names(target: str, instruction: str = "", *, home: Path | None = None) -> list[tuple[str, str]]:
    corpus = load_corpus(home=home)
    return [(skill.name, skill.source) for skill in match_skills(target_hint(target), instruction or target, corpus.skills)]


_DEFAULT_SELECTOR: Any = None


def is_default_skill_selector(selector: Any = None) -> bool:
    from hunter.agent.prompts import current_skill_selector

    return (current_skill_selector() if selector is None else selector) is _DEFAULT_SELECTOR and _DEFAULT_SELECTOR is not None


def install_default_skill_selector() -> None:
    global _DEFAULT_SELECTOR  # noqa: PLW0603
    from hunter.agent.prompts import current_skill_selector, install_skill_selector

    if current_skill_selector() is not None:
        return

    def select(question: str) -> str:
        corpus = load_corpus()
        selected = match_skills(target_hint(question), question, corpus.skills)
        return render_block(selected, corpus_size=len(corpus.skills), notes=corpus.notes)

    _DEFAULT_SELECTOR = select
    install_skill_selector(select)


def _refused(message: str) -> HunterError:
    return HunterError("skills.refused", "config", message, hint="use a simple lowercase skill name under ~/.hunteros/skills")


def write_skill(draft: Any, *, home: Path | None = None) -> Path:
    name = str(getattr(draft, "name", ""))
    if not _ID_RE.fullmatch(name):
        raise _refused(f"skill name is not a safe id: {name!r}")
    root = user_skills_dir(home)
    target_dir = root / name
    target = target_dir / "SKILL.md"
    try:
        resolved_dir = target_dir.resolve()
        within = resolved_dir.is_relative_to(root.resolve())
    except AttributeError:  # Python 3.10 compatibility
        try:
            target_dir.resolve().relative_to(root.resolve())
            within = True
        except ValueError:
            within = False
    if not within:
        raise _refused(f"skill target is outside the user skills directory: {target}")
    if target_dir.exists():
        raise HunterError("skills.exists", "config", f"skill '{name}' already exists", hint="edit the existing card instead")
    description = str(getattr(draft, "description", "")).strip()
    version = str(getattr(draft, "version", "0.1.0"))
    min_tier = str(getattr(draft, "min_tier", "basic"))
    tags = tuple(getattr(draft, "tags", ()) or ())
    body = str(getattr(draft, "body", "")).rstrip()
    quarantined = bool(getattr(draft, "flagged", False))
    lines = ["---", f"name: {name}", f"description: {description}", f"version: {version}", "metadata:", f"  min_tier: {min_tier}", "tags:"]
    lines.extend(f"- {tag}" for tag in tags)
    if quarantined:
        lines.append("quarantined: true")
    text = "\n".join(lines) + "\n---\n\n" + body + "\n"
    if parse_skill_md(text, directory_id=name, source="user") is None:
        raise _refused(f"skill draft '{name}' is not valid")
    try:
        target_dir.mkdir(parents=True, exist_ok=False)
        atomic_write_text(target, text)
    except HunterError:
        raise
    except FileExistsError:
        raise HunterError("skills.exists", "config", f"skill '{name}' already exists", hint="edit the existing card instead") from None
    except OSError as exc:
        raise HunterError("skills.refused", "config", f"could not write skill '{name}': {exc}", hint="check the user skills directory permissions") from None
    return target
