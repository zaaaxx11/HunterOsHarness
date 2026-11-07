# Quick wire: animate_banner on startup + progress line import in engine

# 1. shell.py
p = 'src/hunter/cli/shell.py'
s = open(p).read()
s = s.replace('    from hunter.cli.banner import render_banner',
              '    from hunter.cli.banner import animate_banner', 1)
s = s.replace('    print(render_banner())', '    print(animate_banner())', 1)
open(p, 'w').write(s)
print("shell: done")

# 2. hunt_engine.py
p = 'src/hunter/gateway/hunt_engine.py'
s = open(p).read()
if "from hunter.cli.spinner import" not in s:
    s = s.replace(
        "from hunter.gateway.transport import",
        "from hunter.cli.spinner import ProgressLine, tool_call, tool_result\nfrom hunter.gateway.transport import",
        1,
    )
open(p, 'w').write(s)
print("engine: done")