import json
import subprocess
import sys
from pathlib import Path


def test_eval_all_attacks_refused_control_allowed():
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, str(root / "eval" / "run_eval.py")], check=True, capture_output=True)
    r = json.loads((root / "results" / "eval_results.json").read_text())
    assert all(a["refused"] for a in r["attacks"]) and r["control_refused"] is False
    assert all(s["deferred_catalog_bytes"] < s["eager_bytes"] for s in r["context_size"])
