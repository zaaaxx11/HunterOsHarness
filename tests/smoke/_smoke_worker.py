import os
import time
import json

from pathlib import Path

from hunter.llm.config import HunterConfig, TierConfig, ProviderConfig, AgentConfig
from hunter.llm.native import NativeProvider
from hunter.llm.rate_control import file_gate

os.environ.setdefault("DEVORA_API_KEY", os.environ.get("DEVORA_API_KEY", ""))
pid = os.getpid()
log = Path(os.environ["SMOKE_LOG"])

# Real devora model verified to exist: devora-01/tencent/hy4-flash
provider = NativeProvider(
    HunterConfig(
        model_tiers={
            "orchestrator": TierConfig(
                provider="devora",
                model=os.environ.get("SMOKE_MODEL", "devora-01/tencent/hy4-flash"),
                base_url="https://api.devora.my.id/v1",
                timeout=120,
            )
        },
        providers={"devora": ProviderConfig(api_key=os.environ["DEVORA_API_KEY"], key_env="DEVORA_API_KEY")},
        agent=AgentConfig(api_max_retries=2),
    ),
)

# Measure the dial window from INSIDE the cross-process gate: two real processes
# must never be inside the gate for the same provider at once.
for i in range(3):
    with file_gate.slot("devora", 0.0):
        t0 = time.time()
        r = provider.complete(
            "orchestrator", [{"role": "user", "content": f"reply with the single word: pong{i}"}]
        )
        with log.open("a") as fh:
            fh.write(json.dumps({"pid": pid, "in": t0, "out": time.time(), "ok": bool(r.text)}) + "\n")
