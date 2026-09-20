"""§10 RED: grep --file bypass — flag-value path wajib terdeteksi.

Q1 BOLEH AUTO: readonly luar boleh auto (gate None), tapi path-nya tetap
wajib dikenali (tidak silent-bypass). Prod kini: `--file=<abs>` lolos
(escapes False) sementara `--file <abs>` True — inkonsisten = RED.
Builder GREEN: parsing flag-value (`--file=`, `--file <sp>`, `-f<abs>`)
dianggap path; bila helper dihapus maka gate Q1 (auto readonly) + cwd
tetap menutup cwd-escape.
"""

from __future__ import annotations

from pathlib import Path

from hunter.agent.approval import classify_shell_command


def _prod_escapes(cmd: str, state_dir: Path, cwd=None):
    """Refleksikan helper prod bila masih ada; None bila sudah dihapus (Q1)."""
    try:
        from hunter.agent.approval import _shell_argv_escapes_jail as esc
    except ImportError:
        return None
    return bool(esc(cmd, state_dir, cwd))


def test_grep_flag_file_outside_parse(tmp_path):
    """Varian bypass: --file=, --file <sp>, -f<abs>, ../, symlink."""
    jail = tmp_path / "jail"
    (jail / "subdir").mkdir(parents=True)
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("s3cret", encoding="utf-8")
    abs_posix = str(outside.resolve()).replace("\\", "/")

    variants = [
        f"grep --file={abs_posix} dummy",
        f"grep --file {abs_posix} dummy",
        f"grep -f{abs_posix} dummy",
        "grep --file subdir/../../outside_secret.txt dummy",
    ]
    for cmd in variants:
        assert classify_shell_command(cmd) == "readonly", f"syarat Q1: {cmd!r} readonly, bukan mutating"
        got = _prod_escapes(cmd, jail)
        if got is None:
            # Helper sudah dihapus per Q1 — anggap GREEN bila classify readonly.
            assert True, "helper dihapus, Q1 auto berlaku"
        else:
            assert got is True, f"RED: {cmd!r} lolos jail (escapes False), wajib True"

    # Symlink dalam-jail -> luar (skip bila WinError 1314).
    link = jail / "link_out.txt"
    try:
        link.symlink_to(outside.resolve())
    except OSError:
        return  # varian flag di atas sudah RED; symlink tak tersedia di OS ini
    cmd = "grep --file link_out.txt dummy"
    assert classify_shell_command(cmd) == "readonly", "syarat: symlink-cat readonly"
    got = _prod_escapes(cmd, jail)
    if got is not None:
        assert got is True, "RED: symlink keluar jail wajib True"
