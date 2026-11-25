"""Turn the raw scanner reports in outputs/ into outputs/summary.json and outputs/summary.md.

Every number in the README's results section comes from this script's output, which reads only
the saved reports. It also applies the security gate to the hardened target (exit 1 on failure).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"


def load(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text())


def first(d):
    return d[0] if isinstance(d, list) else d


def semgrep(d):
    c = Counter(r["extra"]["severity"] for r in d["results"])
    return {"error": c["ERROR"], "warning": c["WARNING"], "info": c["INFO"], "total": len(d["results"])}


def bandit(d):
    c = Counter(r["issue_severity"] for r in d["results"])
    return {"high": c["HIGH"], "medium": c["MEDIUM"], "low": c["LOW"], "total": len(d["results"])}


def pip_audit(d):
    deps = [x for x in d["dependencies"] if x.get("vulns")]
    return {"vulnerable_packages": len(deps), "vulnerabilities": sum(len(x["vulns"]) for x in deps)}


def trivy(d):
    vulns = [v for r in d.get("Results", []) for v in (r.get("Vulnerabilities") or [])]
    c = Counter(v["Severity"] for v in vulns)
    fixable_hc = sum(1 for v in vulns if v["Severity"] in ("HIGH", "CRITICAL") and v.get("FixedVersion"))
    return {
        "critical": c["CRITICAL"],
        "high": c["HIGH"],
        "medium": c["MEDIUM"],
        "low": c["LOW"],
        "unknown": c["UNKNOWN"],
        "total": len(vulns),
        "high_critical_fixable": fixable_hc,
        "os": f"{d.get('Metadata', {}).get('OS', {}).get('Family', '?')} {d.get('Metadata', {}).get('OS', {}).get('Name', '?')}",
    }


def gitleaks(d):
    return {"findings": len(d)}


def checkov(d):
    s = first(d)["summary"]
    return {"passed": s["passed"], "failed": s["failed"], "skipped": s["skipped"]}


def hadolint(d):
    c = Counter(x["level"] for x in d)
    return {"error": c["error"], "warning": c["warning"], "info": c["info"] + c["style"]}


def tf_validate(d):
    return {"valid": d["valid"], "errors": d["error_count"], "warnings": d["warning_count"]}


def zap(d):
    alerts = [a for s in d.get("site", []) for a in s.get("alerts", [])]
    c = Counter(int(a["riskcode"]) for a in alerts)
    return {
        "high": c[3],
        "medium": c[2],
        "low": c[1],
        "informational": c[0],
        "alerts": sorted({f"{a['riskdesc'].split(' ')[0]}: {a['alert']}" for a in alerts if int(a["riskcode"]) >= 1}),
    }


PARSERS = {
    "semgrep.json": ("semgrep", semgrep),
    "bandit.json": ("bandit", bandit),
    "pip-audit.json": ("pip_audit", pip_audit),
    "trivy-image.json": ("trivy_image", trivy),
    "gitleaks.json": ("gitleaks", gitleaks),
    "checkov-terraform.json": ("checkov_terraform", checkov),
    "checkov-dockerfile.json": ("checkov_dockerfile", checkov),
    "checkov-github-actions.json": ("checkov_github_actions", checkov),
    "hadolint.json": ("hadolint", hadolint),
    "terraform-validate.json": ("terraform_validate", tf_validate),
    "zap-baseline.json": ("zap_baseline", zap),
    "zap-api.json": ("zap_api", zap),
}

GATE = {  # (tool, metric, description) -> any value > 0 fails the hardened build
    ("semgrep", "error", "Semgrep ERROR-severity findings"),
    ("bandit", "high", "Bandit HIGH-severity findings"),
    ("pip_audit", "vulnerabilities", "known-vulnerable Python dependencies"),
    ("trivy_image", "high_critical_fixable", "HIGH/CRITICAL image CVEs with a fix available"),
    ("gitleaks", "findings", "secrets"),
    ("checkov_terraform", "failed", "failed Checkov Terraform checks"),
    ("checkov_dockerfile", "failed", "failed Checkov Dockerfile checks"),
    ("checkov_github_actions", "failed", "failed Checkov GitHub Actions checks"),
    ("hadolint", "error", "hadolint errors"),
    ("zap_baseline", "high", "ZAP High alerts (baseline)"),
    ("zap_api", "high", "ZAP High alerts (API scan)"),
}


def main() -> int:
    summary: dict = {}
    for target in ("baseline", "hardened"):
        summary[target] = {}
        for filename, (key, parse) in PARSERS.items():
            data = load(OUT / "scans" / target / filename)
            summary[target][key] = parse(data) if data is not None else None
    rt = load(OUT / "redteam" / "results.json")
    if rt:
        summary["redteam"] = rt["summary"]

    failures = []
    for tool, metric, desc in sorted(GATE):
        res = summary["hardened"].get(tool)
        if res is None:
            failures.append(f"missing report: {tool}")
        elif res[metric]:
            failures.append(f"{res[metric]} {desc}")
    if rt and rt["summary"]["hardened"]["successful"]:
        failures.append(f"{rt['summary']['hardened']['successful']} successful prompt-injection attacks")
    summary["gate"] = {"passed": not failures, "failures": failures}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (OUT / "summary.md").write_text(render(summary))
    print((OUT / "summary.md").read_text())
    return 0 if not failures else 1


def fmt(res, keys):
    if res is None:
        return "not run"
    return ", ".join(f"{res[k]} {k.replace('_', ' ')}" for k in keys)


def render(s) -> str:
    rows = [
        ("SAST", "Semgrep (p/python, p/owasp-top-ten, custom LLM rules)", "semgrep", ["error", "warning", "info"]),
        ("SAST", "Bandit", "bandit", ["high", "medium", "low"]),
        ("SCA", "pip-audit (Python dependencies)", "pip_audit", ["vulnerable_packages", "vulnerabilities"]),
        ("SCA", "Trivy (container image)", "trivy_image", ["critical", "high", "medium", "low", "high_critical_fixable"]),
        ("Secrets", "gitleaks", "gitleaks", ["findings"]),
        ("IaC", "Checkov (Terraform)", "checkov_terraform", ["failed", "passed", "skipped"]),
        ("IaC", "terraform validate", "terraform_validate", ["valid", "errors"]),
        ("Container", "Checkov (Dockerfile)", "checkov_dockerfile", ["failed", "passed"]),
        ("Container", "hadolint", "hadolint", ["error", "warning", "info"]),
        ("CI/CD", "Checkov (GitHub Actions workflow)", "checkov_github_actions", ["failed", "passed"]),
        ("DAST", "OWASP ZAP baseline (passive)", "zap_baseline", ["high", "medium", "low", "informational"]),
        ("DAST", "OWASP ZAP API scan (active, OpenAPI)", "zap_api", ["high", "medium", "low", "informational"]),
    ]
    lines = ["| Stage | Scanner | Baseline (vulnerable/) | Hardened |", "|---|---|---|---|"]
    for stage, name, key, keys in rows:
        lines.append(f"| {stage} | {name} | {fmt(s['baseline'][key], keys)} | {fmt(s['hardened'][key], keys)} |")
    if "redteam" in s:
        rt = s["redteam"]
        lines.append(
            f"| LLM red team | Prompt-injection / jailbreak corpus | {rt['vulnerable']['successful']} of "
            f"{rt['vulnerable']['attacks']} attacks succeeded | {rt['hardened']['successful']} of "
            f"{rt['hardened']['attacks']} attacks succeeded |"
        )
    lines.append("")
    gate = s["gate"]
    lines.append("**Security gate (hardened): " + ("PASSED**" if gate["passed"] else "FAILED**: " + "; ".join(gate["failures"])))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
