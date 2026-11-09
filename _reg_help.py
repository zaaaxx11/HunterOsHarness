"""Register /help as a command in the registry."""
p = 'src/hunter/cli/commands/registry.py'
s = open(p).read()

# Add _help_handler function
add = """
def _help_handler(args_str: str, session: Any) -> str:
    \"\"\"Built-in /help handler.\"\"\"
    name = args_str.strip().lstrip(\"/\").split(\" \")[0].lower()
    return help_detail(name) if name else help_text()

"""
idx = s.index('def dispatch(line: str, session: Any) -> str:')
s = s[:idx] + add + s[idx:]

# Register /help in ensure_core — at the end, before _grouped
register_block = """
    REGISTRY.setdefault("help", Command(
        name="help",
        description="Show all commands or detail for one",
        arg_hint="[command]",
        category="Chat",
        handler=_help_handler,
        manual="Show the full command list grouped by category, or detailed help for one command. /help hunt shows /hunt with its manual, usage, and examples.",
        aliases=("?",),
    ))
"""
idx3 = s.index('\ndef _grouped() -> list[tuple[str, list[Command]]]:')
s = s[:idx3] + register_block + s[idx3:]

open(p, 'w').write(s)
print("/help registered")