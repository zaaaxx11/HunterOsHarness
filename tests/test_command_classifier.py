"""M9-A command policy tests.

The classifier is pure policy: it never executes a command, and a readonly
classification is only possible for the small pinned argv allowlist. Unknown,
malformed, shell-syntax, and write-shaped commands fail closed as mutating.
"""

from __future__ import annotations


def test_classify_shell_command_readonly_mutating_catastrophic():
    from hunter.agent.approval import classify_shell_command

    cases = [
        ("pwd", "readonly"),
        ("git status", "readonly"),
        ("git --no-pager diff --stat", "readonly"),
        ("echo hello", "readonly"),
        ("touch marker", "mutating"),
        ("git commit -am message", "mutating"),
        ("python -c print(1)", "mutating"),
        ("cat --output result.txt input.txt", "mutating"),
        ("echo hello > result.txt", "mutating"),
        ("rm -rf /", "catastrophic"),
        ("format C:", "catastrophic"),
    ]
    for command, expected in cases:
        assert classify_shell_command(command) == expected, command


def test_classify_shell_command_raw_quoted_and_escaped_normalization():
    from hunter.agent.approval import classify_shell_command

    cases = [
        ('"for""mat" c:', "catastrophic"),
        ('r"m" -rf /', "catastrophic"),
        ("^format c:", "catastrophic"),
        (r"c:\\windows\\system32\\format.com c:", "catastrophic"),
    ]
    for command, expected in cases:
        assert classify_shell_command(command) == expected, command


def test_unknown_shell_command_defaults_mutating():
    from hunter.agent.approval import classify_shell_command

    cases = ["unknown-binary --version", '"unterminated', "echo hi | cat", "NAME=value pwd"]
    for command in cases:
        assert classify_shell_command(command) == "mutating", command


def test_classifier_never_false_readonly_for_redirect_install_or_write():
    from hunter.agent.approval import classify_shell_command

    cases = [
        "install package destination",
        "grep --write matches input",
        "git diff --output=patch.txt",
        "cat --append output input",
    ]
    for command in cases:
        assert classify_shell_command(command) == "mutating", command


def test_classifier_exports_pinned_policy_constants_in_order():
    from hunter.agent.approval import READONLY_EXECUTABLES, READONLY_GIT_SUBCOMMANDS

    assert READONLY_EXECUTABLES == (
        "cat",
        "cd",
        "dir",
        "echo",
        "find",
        "grep",
        "head",
        "hostname",
        "id",
        "ls",
        "pwd",
        "rg",
        "stat",
        "tail",
        "type",
        "uname",
        "ver",
        "where",
        "which",
        "whoami",
        "git",
    )
    assert READONLY_GIT_SUBCOMMANDS == (
        "status",
        "diff",
        "log",
        "show",
        "branch",
        "rev-parse",
        "ls-files",
    )
