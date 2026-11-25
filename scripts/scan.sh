#!/usr/bin/env bash
# Run every static scanner against one target and save the raw reports under outputs/scans/<target>/.
#   scripts/scan.sh hardened    src/, requirements.txt, docqa:scan image, infra/terraform, Dockerfile
#   scripts/scan.sh baseline    vulnerable/ (same scanners, same rules)
# Scanners run from their official Docker images (pinned by digest below) or the tools venv, so
# results do not depend on what is installed on the host. Exit codes are ignored here: the
# pass/fail gate is applied by CI (.github/workflows/security.yml) and by scripts/summarize_scans.py.
set -uo pipefail

TARGET="${1:?usage: scan.sh hardened|baseline}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="outputs/scans/$TARGET"
TOOLS="$ROOT/.venv-tools/bin"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/secure-llm-api-pipeline"
mkdir -p "$ROOT/$OUT" "$CACHE/trivy"
cd "$ROOT"

SEMGREP_IMG="semgrep/semgrep@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1"   # 1.186.0
TRIVY_IMG="aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"       # 0.76.2
GITLEAKS_IMG="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f" # 8.30.1
HADOLINT_IMG="hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d"    # 2.15.1

case "$TARGET" in
  hardened) CODE="src infra Dockerfile"; REQ=requirements.txt;            IMAGE=docqa:scan;            TF=infra/terraform;  DF=Dockerfile ;;
  baseline) CODE=vulnerable;   REQ=vulnerable/requirements.txt; IMAGE=docqa-vulnerable:scan; TF=vulnerable/infra; DF=vulnerable/Dockerfile ;;
  *) echo "unknown target: $TARGET" >&2; exit 2 ;;
esac

echo "[$TARGET] semgrep (SAST: p/python + p/owasp-top-ten + .semgrep custom LLM rules)"
docker run --rm -v "$ROOT":/src -w /src "$SEMGREP_IMG" semgrep scan --metrics=off --quiet \
  --config p/python --config p/owasp-top-ten --config .semgrep/ \
  --json-output="$OUT/semgrep.json" --sarif-output="$OUT/semgrep.sarif" $CODE >/dev/null

echo "[$TARGET] bandit (SAST)"
"$TOOLS/bandit" -q -c pyproject.toml -r ${CODE%% *} -f json -o "$OUT/bandit.json"
"$TOOLS/bandit" -q -c pyproject.toml -r ${CODE%% *} -f sarif -o "$OUT/bandit.sarif" 2>/dev/null || true

echo "[$TARGET] pip-audit (SCA: Python dependencies)"
"$TOOLS/pip-audit" -r "$REQ" --no-deps --disable-pip --format json --output "$OUT/pip-audit.json" >/dev/null 2>&1

echo "[$TARGET] trivy (SCA: container image OS + language packages)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$CACHE/trivy":/root/.cache -v "$ROOT/$OUT":/out \
  "$TRIVY_IMG" image --quiet --scanners vuln --format json --output /out/trivy-image.json "$IMAGE"
docker run --rm -v "$CACHE/trivy":/root/.cache -v "$ROOT/$OUT":/out \
  "$TRIVY_IMG" convert --quiet --format sarif --output /out/trivy-image.sarif /out/trivy-image.json

echo "[$TARGET] gitleaks (secrets)"
if [ "$TARGET" = hardened ]; then
  docker run --rm -v "$ROOT":/repo -w /repo "$GITLEAKS_IMG" dir . --config .gitleaks.toml \
    --report-format json --report-path "$OUT/gitleaks.json" --no-banner --redact >/dev/null 2>&1
else
  docker run --rm -v "$ROOT":/repo -w /repo "$GITLEAKS_IMG" dir vulnerable \
    --report-format json --report-path "$OUT/gitleaks.json" --no-banner --redact >/dev/null 2>&1
fi

echo "[$TARGET] checkov (IaC: Terraform + Dockerfile)"
"$TOOLS/checkov" -d "$TF" --framework terraform --quiet --compact -o json >"$OUT/checkov-terraform.json" 2>/dev/null
"$TOOLS/checkov" -f "$DF" --framework dockerfile --quiet --compact -o json >"$OUT/checkov-dockerfile.json" 2>/dev/null
if [ "$TARGET" = hardened ]; then  # the baseline has no pipeline of its own
  "$TOOLS/checkov" -d .github --framework github_actions --quiet --compact -o json >"$OUT/checkov-github-actions.json" 2>/dev/null
fi

echo "[$TARGET] hadolint (Dockerfile lint)"
docker run --rm -i "$HADOLINT_IMG" hadolint -f json - <"$DF" >"$OUT/hadolint.json"

# Reports must not carry the absolute path of the machine that produced them.
for f in "$OUT"/*.json "$OUT"/*.sarif; do [ -f "$f" ] && sed -i.bak "s|$ROOT|.|g" "$f" && rm -f "$f.bak"; done

echo "[$TARGET] done -> $OUT"
