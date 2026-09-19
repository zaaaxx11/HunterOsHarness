"""PracticeVault behavior tests — pins all nine planted vulnerabilities.

Uses httpx (already a core dependency). Note: httpx does NOT follow redirects
by default, which is exactly what the open-redirect test needs.
"""

import httpx
import pytest

from hunter.vault.server import start_server

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture()
def vault(monkeypatch):
    # Keep loopback traffic out of any ambient proxy configuration.
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    handle, port = start_server()
    try:
        yield handle, port
    finally:
        handle.shutdown()


def test_ephemeral_port_and_home_page(vault):
    handle, port = start_server()
    try:
        assert port == handle.port and port != 0
        assert handle.url == f"http://127.0.0.1:{port}"
        resp = httpx.get(f"{handle.url}/", timeout=5)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        for href in ("/search?q=hunter", "/login", "/download?file=readme.txt",
                     "/goto", "/transfer", "/admin", "/static/", "/backup/users.sql"):
            assert f'href="{href}"' in resp.text
    finally:
        handle.shutdown()


def test_missing_security_headers_on_every_response(vault):
    handle, _ = vault
    for path in ("/", "/search", "/login"):
        resp = httpx.get(f"{handle.url}{path}", timeout=5)
        headers = {k.lower() for k in resp.headers}
        assert "content-security-policy" not in headers
        assert "x-frame-options" not in headers
        assert "x-content-type-options" not in headers


def test_directory_listing_with_links(vault):
    handle, _ = vault
    resp = httpx.get(f"{handle.url}/static/", timeout=5)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "<a href" in resp.text
    assert "Directory listing for /static/" in resp.text


def test_reflected_xss_raw_echo(vault):
    handle, _ = vault
    canary = "hun<x>ter<b>q9"
    resp = httpx.get(f"{handle.url}/search?q=hun%3Cx%3Eter%3Cb%3Eq9", timeout=5)
    assert resp.status_code == 200
    assert canary in resp.text  # raw, unescaped


def test_sql_error_on_quote_in_username(vault):
    handle, _ = vault
    resp = httpx.post(
        f"{handle.url}/login",
        data={"username": "'", "password": "hunter"},
        timeout=5,
    )
    assert resp.status_code == 500
    assert "SQLite" in resp.text
    assert "syntax error" in resp.text


def test_login_success_sets_role_cookie(vault):
    handle, _ = vault
    resp = httpx.post(
        f"{handle.url}/login",
        data={"username": "admin", "password": "admin123"},
        timeout=5,
    )
    assert resp.status_code == 200
    assert "role=user" in resp.headers.get("set-cookie", "")


def test_login_bad_credentials_rejected(vault):
    handle, _ = vault
    resp = httpx.post(
        f"{handle.url}/login",
        data={"username": "admin", "password": "wrong"},
        timeout=5,
    )
    assert resp.status_code == 401


def test_path_traversal_serves_outside_file(vault):
    handle, _ = vault
    for query in ("../../secret.txt", "..%2f..%2fsecret.txt"):
        resp = httpx.get(f"{handle.url}/download?file={query}", timeout=5)
        assert resp.status_code == 200, query
        assert "root:x:0:0:" in resp.text, query


def test_download_without_traversal_stays_inside(vault):
    handle, _ = vault
    resp = httpx.get(f"{handle.url}/download?file=readme.txt", timeout=5)
    assert resp.status_code == 200
    assert "root:x:0:0:" not in resp.text
    resp = httpx.get(f"{handle.url}/download?file=../../nope.txt", timeout=5)
    assert resp.status_code == 404


def test_open_redirect_302_to_external(vault):
    handle, _ = vault
    resp = httpx.get(f"{handle.url}/goto?url=https://evil.example.com/", timeout=5)
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://evil.example.com/"


def test_unauthenticated_transfer_succeeds(vault):
    handle, _ = vault
    resp = httpx.post(
        f"{handle.url}/transfer",
        data={"from": "1", "to": "2", "amount": "100"},
        timeout=5,
    )
    assert resp.status_code == 200  # no auth/cookie of any kind was sent
    assert "Transfer complete" in resp.text


def test_admin_auth_bypass_via_forgeable_cookie(vault):
    handle, _ = vault
    bare = httpx.get(f"{handle.url}/admin", timeout=5)
    assert bare.status_code == 403

    as_user = httpx.get(f"{handle.url}/admin", headers={"Cookie": "role=user"}, timeout=5)
    assert as_user.status_code == 403

    forged = httpx.get(f"{handle.url}/admin", headers={"Cookie": "role=admin"}, timeout=5)
    assert forged.status_code == 200
    assert "Admin panel" in forged.text


def test_backup_users_sql_exposed(vault):
    handle, _ = vault
    resp = httpx.get(f"{handle.url}/backup/users.sql", timeout=5)
    assert resp.status_code == 200
    assert "username,md5hash" in resp.text
    assert "admin,21232f297a57a5a743894a0e4a801fc3" in resp.text


def test_unknown_paths_404(vault):
    handle, _ = vault
    for path in ("/nope", "/static/missing.css", "/backup/other.sql"):
        resp = httpx.get(f"{handle.url}{path}", timeout=5)
        assert resp.status_code == 404, path


def test_state_changing_methods_rejected(vault):
    handle, _ = vault
    for method in ("PUT", "DELETE", "TRACE"):
        resp = httpx.request(method, f"{handle.url}/", timeout=5)
        assert resp.status_code in (405, 501), method


def test_responses_are_deterministic(vault):
    handle, _ = vault
    first = httpx.get(f"{handle.url}/search?q=hunter", timeout=5)
    second = httpx.get(f"{handle.url}/search?q=hunter", timeout=5)
    assert first.status_code == second.status_code
    assert first.text == second.text
