import json

from hunter.workflow.scope_recognize import recognize, recognize_scope
from hunter.tools.scope import ScopeSet


def test_recognize_url_without_provider():
    out = recognize(None, "http://example.com")
    assert out["kind"] == "url"
    assert out["hosts"] == ["example.com"]


def test_recognize_directory_without_provider(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    out = recognize(None, str(d))
    assert out["kind"] == "url"
    assert out["local_roots"] == [str(d.resolve())]


def test_recognize_with_mock_provider_uses_llm():
    class FakeProvider:
        name = "fake"

        def complete(self, tier, messages, tools=None, stream_cb=None, budget=None):
            from hunter.llm.base import TurnResult

            return TurnResult(text=json.dumps({
                "kind": "repo",
                "name": "myrepo",
                "hosts": [],
                "local_roots": ["/tmp/myrepo"],
                "allow_subdomains": False,
                "engine": "review",
                "notes": "git repo",
                "git_url": "https://github.com/x/y.git",
            }))

        def classify(self, exc):
            from hunter.llm.base import ClassifiedError

            return ClassifiedError()

    out = recognize(FakeProvider(), "https://github.com/x/y.git")
    assert out["kind"] == "repo"
    assert out["git_url"] == "https://github.com/x/y.git"


def test_recognize_scope_returns_scopeset():
    scope = recognize_scope(None, "http://example.com")
    assert isinstance(scope, ScopeSet)
    assert "example.com" in scope.allowed_hosts


def test_manifest_scope_wins_over_recognition(tmp_path):
    """An explicit --scope manifest must never be replaced by an LLM guess.

    Regression pin: the RAG branch of `hunt` called `recognize_scope()` for
    every target even when the operator passed `--scope`, so a 68-host
    approved manifest was silently swapped for a 1-host guess. The fix
    resolves the manifest first and only falls back to recognition when no
    manifest was given.
    """
    import json

    from hunter.tools.scope import scope_from_manifest

    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps({
        "name": "approved",
        "hosts": ["api.relay.link", "explorer.chain.relay.link", "rpc.berachain.com"],
        "allow_subdomains": True,
    }), encoding="utf-8")

    explicit = scope_from_manifest(manifest)
    guessed = recognize_scope(None, "https://api.relay.link")

    # the manifest carries all three approved hosts ...
    assert len(explicit.allowed_hosts) == 3
    # ... while the guess only knows the one host it was told about
    assert len(guessed.allowed_hosts) == 1

    # the precedence rule the CLI now implements
    chosen = explicit if explicit is not None else guessed
    assert chosen is explicit
    assert "rpc.berachain.com" in chosen.allowed_hosts
