PY    := .venv/bin/python
TOOLS := .venv-tools/bin

.PHONY: venv tools lock keys test redteam serve docker-build docker-build-vulnerable docker-run \
        scan-baseline scan-hardened dast-baseline dast-hardened tf-validate summary all clean

venv:            ## app + test environment
	python3.11 -m venv .venv
	.venv/bin/pip install --require-hashes -r requirements.txt
	.venv/bin/pip install -r requirements-dev.txt

tools:           ## Python-based scanners (bandit, pip-audit, checkov) in their own venv
	python3.11 -m venv .venv-tools && $(TOOLS)/pip install -r requirements-tools.txt

lock:            ## re-generate the hash-pinned requirements.txt from requirements.in
	.venv/bin/pip install pip-tools && .venv/bin/pip-compile --generate-hashes --strip-extras --allow-unsafe --no-emit-index-url -o requirements.txt requirements.in

keys:            ## random per-user API keys for local runs (.dev-keys) and their hashes (.env)
	$(PY) scripts/make_dev_keys.py

test:
	$(PY) -m pytest -q --junitxml=outputs/tests/junit.xml | tee outputs/tests/pytest.txt

redteam:         ## prompt-injection corpus vs vulnerable / hardened, writes outputs/redteam/
	$(PY) scripts/redteam_eval.py

serve: keys
	set -a && . ./.env && set +a && PYTHONPATH=src .venv/bin/uvicorn docqa.api:app_from_env --factory --host 127.0.0.1 --port 8000

docker-build:
	docker build -t docqa:scan .

docker-build-vulnerable:
	docker build -f vulnerable/Dockerfile -t docqa-vulnerable:scan .

docker-run: keys docker-build
	docker compose up

scan-baseline: docker-build-vulnerable
	scripts/scan.sh baseline

scan-hardened: docker-build
	scripts/scan.sh hardened

dast-baseline: docker-build-vulnerable
	scripts/dast.sh baseline

dast-hardened: docker-build
	scripts/dast.sh hardened

tf-validate:     ## fmt + validate only. Never `terraform apply`; no cloud credentials are used.
	cd infra/terraform && terraform fmt -check -recursive && terraform init -backend=false -input=false && terraform validate

summary:         ## outputs/summary.{json,md} from the saved reports; exits 1 if the hardened gate fails
	$(PY) scripts/summarize_scans.py

all: test redteam scan-baseline scan-hardened dast-baseline dast-hardened summary

clean:
	rm -rf .pytest_cache outputs/zap
