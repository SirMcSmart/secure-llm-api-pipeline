"""Run the prompt-injection / jailbreak corpus against three targets and write
outputs/redteam/results.json and outputs/redteam/summary.md.

Targets:
  vulnerable            vulnerable/app.py
  hardened-no-filters   hardened service with the heuristic input and context filters switched off
                        (shows the authorization boundary and output handling hold on their own)
  hardened              hardened service, all layers on (the deployed configuration)
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from redteam_lib import CORPUS, hardened, run_attack, vulnerable  # noqa: E402

OUT = ROOT / "outputs" / "redteam"


def main() -> int:
    targets = [vulnerable(), hardened("hardened-no-filters", input_guard=False, context_guard=False), hardened()]
    rows = [run_attack(t, a) for a in CORPUS for t in targets]
    by_attack = {a["id"]: a for a in CORPUS}
    summary: dict[str, dict] = {}
    for t in targets:
        mine = [r for r in rows if r["target"] == t.name and by_attack[r["id"]]["category"] != "control_benign"]
        cats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in mine:
            c = cats[by_attack[r["id"]]["category"]]
            c[0] += r["success"]
            c[1] += 1
        summary[t.name] = {
            "attacks": len(mine),
            "successful": sum(r["success"] for r in mine),
            "by_category": {k: {"successful": v[0], "attacks": v[1]} for k, v in sorted(cats.items())},
        }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps({"summary": summary, "results": rows}, indent=2) + "\n")

    names = [t.name for t in targets]
    lines = ["| Attack | Category | OWASP LLM | ATLAS | " + " | ".join(names) + " |", "|---|---|---|---|" + "---|" * len(names)]
    for a in CORPUS:
        cells = []
        for n in names:
            r = next(x for x in rows if x["id"] == a["id"] and x["target"] == n)
            cells.append("**succeeded**" if r["success"] else f"blocked ({r['status']})" if r["status"] != 200 else "failed")
        lines.append(f"| {a['id']} | {a['category']} | {a['owasp']} | {a['atlas']} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("| Target | Successful attacks (excluding benign control) |")
    lines.append("|---|---:|")
    for n in names:
        lines.append(f"| {n} | {summary[n]['successful']} / {summary[n]['attacks']} |")
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[-(len(names) + 2):]))
    # CI gate: any successful attack against the deployed configuration fails the build.
    return 1 if summary["hardened"]["successful"] else 0


if __name__ == "__main__":
    sys.exit(main())
