#!/usr/bin/env bash
# DAST with OWASP ZAP against the running container of one target.
#   scripts/dast.sh hardened|baseline
# 1. zap-baseline.py   passive scan (headers, cookies, information leaks)
# 2. zap-api-scan.py   active scan driven by the OpenAPI spec, authenticated as "alice"
# JSON reports go to outputs/scans/<target>/zap-*.json; HTML reports to outputs/zap/ (git-ignored).
set -uo pipefail

TARGET="${1:?usage: dast.sh hardened|baseline}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ZAP_IMG="${ZAP_IMG:-ghcr.io/zaproxy/zaproxy:stable}"
NET=docqa-dast
WRK="$(mktemp -d)"
chmod 777 "$WRK"
OUT="outputs/scans/$TARGET"
mkdir -p "$OUT" outputs/zap

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f docqa-dast-app >/dev/null 2>&1 || true

if [ "$TARGET" = hardened ]; then
  KEY="dq_dast_$(openssl rand -hex 24)"
  HASH="$(printf '%s' "$KEY" | shasum -a 256 | cut -d' ' -f1)"
  # Same runtime restrictions as production. The per-user rate limit is raised so the scanner is
  # not throttled into testing nothing (the WAF rate rule is the production limit).
  docker run -d --name docqa-dast-app --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges -e DOCQA_API_KEY_HASHES="{\"$HASH\":\"alice\"}" \
    -e DOCQA_RATE_LIMIT_PER_MINUTE=100000 docqa:scan >/dev/null
else
  KEY="alice123"
  docker run -d --name docqa-dast-app --network "$NET" docqa-vulnerable:scan >/dev/null
fi
sleep 5

"$ROOT/.venv/bin/python" scripts/export_openapi.py "$TARGET" "$WRK/openapi.json" "http://docqa-dast-app:8000" >/dev/null

# The packaged ZAP scans add this header to every request.
AUTH=(-e ZAP_AUTH_HEADER=Authorization -e "ZAP_AUTH_HEADER_VALUE=Bearer $KEY")

echo "[$TARGET] ZAP baseline (passive)"
docker run --rm --network "$NET" "${AUTH[@]}" -v "$WRK":/zap/wrk:rw "$ZAP_IMG" zap-baseline.py \
  -t http://docqa-dast-app:8000/health -J zap-baseline.json -r zap-baseline.html -I >"$WRK/baseline.log" 2>&1

echo "[$TARGET] ZAP API scan (active, OpenAPI, authenticated)"
docker run --rm --network "$NET" "${AUTH[@]}" -v "$WRK":/zap/wrk:rw "$ZAP_IMG" zap-api-scan.py \
  -t /zap/wrk/openapi.json -f openapi -O http://docqa-dast-app:8000 \
  -J zap-api.json -r zap-api.html -I >"$WRK/api.log" 2>&1

cp "$WRK/zap-baseline.json" "$WRK/zap-api.json" "$OUT/" 2>/dev/null
cp "$WRK/zap-baseline.html" "outputs/zap/$TARGET-zap-baseline.html" 2>/dev/null
cp "$WRK/zap-api.html" "outputs/zap/$TARGET-zap-api.html" 2>/dev/null
for f in "$OUT"/zap-*.json; do [ -f "$f" ] && sed -i.bak "s|$ROOT|.|g" "$f" && rm -f "$f.bak"; done
tail -3 "$WRK/api.log"
docker rm -f docqa-dast-app >/dev/null
rm -rf "$WRK"
echo "[$TARGET] done -> $OUT/zap-*.json"
