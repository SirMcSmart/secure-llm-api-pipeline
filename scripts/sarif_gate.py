"""Fail (exit 1) if a SARIF file has results at or above a security-severity threshold.
Used for CodeQL, whose action uploads results but does not fail the job by itself.
  python scripts/sarif_gate.py results.sarif [--min 7.0]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif", nargs="+", type=Path)
    ap.add_argument("--min", type=float, default=7.0, help="security-severity threshold (7.0 = high)")
    args = ap.parse_args()
    blocking = []
    for path in args.sarif:
        for run in json.loads(path.read_text()).get("runs", []):
            rules = {}
            for comp in [run["tool"]["driver"], *run["tool"].get("extensions", [])]:
                for rule in comp.get("rules", []):
                    rules[rule["id"]] = rule
            for res in run.get("results", []):
                sev = float(rules.get(res.get("ruleId"), {}).get("properties", {}).get("security-severity", 0) or 0)
                if sev >= args.min:
                    loc = res["locations"][0]["physicalLocation"]
                    blocking.append(f"{sev:4.1f} {res['ruleId']} {loc['artifactLocation']['uri']}:{loc['region']['startLine']}")
    print("\n".join(blocking) or f"no results with security-severity >= {args.min}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
