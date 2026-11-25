"""Write the OpenAPI spec of the hardened or vulnerable app (for the ZAP API scan) without
enabling /openapi.json in the running service."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

target, out, server = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
if target == "hardened":
    from docqa.api import create_app
    from docqa.config import Settings

    spec = create_app(Settings(enable_docs=True)).openapi()
else:
    s = importlib.util.spec_from_file_location("vulnerable_app", ROOT / "vulnerable" / "app.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    spec = m.app.openapi()
spec["servers"] = [{"url": server}]
out.write_text(json.dumps(spec, indent=2))
print(f"wrote {out}")
