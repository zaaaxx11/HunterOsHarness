import json
from pathlib import Path

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
