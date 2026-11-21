import os
import time
import json

from pathlib import Path

from hunter.llm.config import HunterConfig, TierConfig, ProviderConfig, AgentConfig
from hunter.llm.native import NativeProvider
from hunter.llm.rate_control import file_gate

pid = os.getpid()
log = Path(os.environ["SMOKE_LOG"])


class FakeTransport:
    def post(self, url, json=None, headers=None):
        class R:
            status_code = 200

            def json(self):
                return {
                    "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                    "usage": {},
                }

            text = ""

        time.sleep(0.3)
        return R()


provider = NativeProvider(
    HunterConfig(
        model_tiers={"orchestrator": TierConfig(provider="devora", model="m", base_url="https://x.test/v1")},
        providers={"devora": ProviderConfig(api_key="k")},
        agent=AgentConfig(api_max_retries=1),
    ),
    transport=FakeTransport(),
)

# Measure the window from INSIDE the cross-process gate, so the lock-wait that
# complete() does internally is not counted as "dial time". Two processes must
# never be inside the gate for the same provider at once.
for i in range(5):
    with file_gate.slot("devora", 0.0):
        t0 = time.time()
        provider.complete("orchestrator", [{"role": "user", "content": f"hi {i}"}])
        with log.open("a") as fh:
            fh.write(json.dumps({"pid": pid, "in": t0, "out": time.time()}) + "\n")
