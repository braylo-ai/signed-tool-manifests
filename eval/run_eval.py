"""Attack suite + deferred-loading size measurement. Writes results/eval_results.json."""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from stm.manifest import TrustStore, key_id, sign  # noqa: E402
from stm.registry import Registry  # noqa: E402
from stm.runtime import AgentRuntime, ToolRefused  # noqa: E402

NOW = 1_700_000_000


def make_tool(i):
    return {"name": f"tool_{i:03d}", "version": "1.0.0",
            "description": f"Synthetic tool {i}: performs operation {i} on a record and returns a status object.",
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": {"record_id": {"type": "string", "maxLength": 64, "description": "Record id."},
                                           "mode": {"type": "string", "enum": ["dry_run", "apply"]},
                                           "limit": {"type": "integer", "minimum": 1, "maximum": 100}},
                            "required": ["record_id"]}}


def setup(n=3):
    key = Ed25519PrivateKey.generate()
    reg = Registry("acme", key, clock=lambda: NOW)
    for i in range(n):
        reg.publish(make_tool(i))
    trust = TrustStore(); trust.add("acme", key.public_key())
    rt = AgentRuntime(trust, reg.fetch_definition, {f"tool_{i:03d}": (lambda a: "ok") for i in range(n)}, clock=lambda: NOW)
    return key, reg, trust, rt


def attack(name, fn):
    key, reg, trust, rt = setup()
    try:
        fn(key, reg, trust, rt)
        return {"attack": name, "refused": False, "code": None}
    except ToolRefused as e:
        return {"attack": name, "refused": True, "code": e.code}


def tamper_def(k, r, t, rt):
    rt.install(r.release()); real = rt.fetch
    rt.fetch = lambda n, v: dict(real(n, v), description="evil")
    rt.call("tool_000", {"record_id": "a"})


def tamper_schema(k, r, t, rt):
    rt.install(r.release()); real = rt.fetch

    def f(n, v):
        d = real(n, v); d["inputSchema"]["additionalProperties"] = True; return d
    rt.fetch = f
    rt.call("tool_000", {"record_id": "a", "exfil": "x"})


def tamper_manifest(k, r, t, rt):
    m = r.release(); m["body"]["tools"][0]["version"] = "9.9.9"; rt.install(m)


def unsigned(k, r, t, rt):
    rt.install(r.release()["body"])


def foreign_key(k, r, t, rt):
    rt.install(sign(r.release()["body"], Ed25519PrivateKey.generate()))


def revoked(k, r, t, rt):
    t.revoke(key_id(k.public_key())); rt.install(r.release())


def expired(k, r, t, rt):
    m = r.release(ttl=10); rt.clock = lambda: NOW + 11; rt.install(m)


def replay(k, r, t, rt):
    old = r.release(); rt.install(r.release()); rt.install(old)


def downgrade(k, r, t, rt):
    t2 = make_tool(0); t2["version"] = "1.1.0"; t2["inputSchema"]["properties"]["note"] = {"type": "string"}
    r.publish(t2); rt.install(r.release()); r.current["tool_000"] = "1.0.0"; rt.install(r.release())


def drift(k, r, t, rt):
    rt.install(r.release()); real = rt.fetch
    rt.fetch = lambda n, v: dict(real(n, v), version="1.0.1"); rt.load("tool_001")


def unknown_tool(k, r, t, rt):
    rt.install(r.release()); rt.call("tool_999", {})


def control(k, r, t, rt):  # legitimate use: must NOT be refused
    rt.install(r.release()); rt.call("tool_000", {"record_id": "a"})


attacks = [attack(n, f) for n, f in [
    ("tampered description in transit", tamper_def), ("tampered schema in transit", tamper_schema),
    ("tampered manifest body", tamper_manifest), ("unsigned manifest", unsigned),
    ("signed by untrusted key", foreign_key), ("signed by revoked key", revoked),
    ("expired manifest", expired), ("replay of older manifest", replay),
    ("tool version downgrade", downgrade), ("schema drift (wrong version served)", drift),
    ("tool not in any manifest", unknown_tool)]]
ctrl = attack("legitimate signed call (control)", control)

sizes = []
for n in (10, 50, 200):
    _, reg, _, rt = setup(n); rt.install(reg.release())
    eager, deferred = rt.context_bytes(deferred=False), rt.context_bytes(deferred=True)
    sizes.append({"tools": n, "eager_bytes": eager, "deferred_catalog_bytes": deferred,
                  "reduction": round(1 - deferred / eager, 3)})

out = {"attacks_refused": f"{sum(a['refused'] for a in attacks)}/{len(attacks)}", "attacks": attacks,
       "control_refused": ctrl["refused"], "context_size": sizes}
(ROOT / "results").mkdir(exist_ok=True)
(ROOT / "results" / "eval_results.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps(out, indent=2))
