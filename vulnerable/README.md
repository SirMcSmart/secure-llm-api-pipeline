# vulnerable/ : the "before" picture

**Do not deploy anything in this folder.** It is the DocQA feature as it might look before a
security review: it works, and it has the flaws below planted on purpose. The same scanners and
the same red-team corpus run against it and against the hardened service in `src/docqa/`, so the
before/after numbers in the main README compare like with like.

Every flaw is proven exploitable by a passing test in `tests/test_vulnerable_baseline.py`.

| ID | Flaw | CWE | OWASP | Found by | Fixed in |
|---|---|---|---|---|---|
| VULN-01 | SQL built with `%` formatting in `/v1/search` | CWE-89 | A03 Injection | Bandit B608, ZAP API scan, `test_vuln01_*` | `store.py` (literal parameterised queries) |
| VULN-02 | IDOR: `/v1/documents/{id}` checks login, not ownership | CWE-639 | A01 Broken Access Control | `test_vuln02_*` (no SAST tool can know the business rule) | `store.py` `SQL_GET` |
| VULN-03 | Hard-coded signing secret and admin token | CWE-798 | A07 | gitleaks (1 of 2 found), Bandit B105 | keys generated per environment, AWS Secrets Manager |
| VULN-04 | Short guessable API keys, stored as unsalted MD5, accepted in the URL | CWE-328, CWE-598 | A02, A07 | Bandit B324, Semgrep md5 rules | `auth.py` |
| VULN-05 | Retrieval over every tenant's documents; the *prompt* is asked to enforce access | CWE-285 | LLM01, LLM02, LLM08 | custom Semgrep `authorization-delegated-to-prompt`, red team PI-* | `api.py` + `store.readable_by` (authorize before retrieval) |
| VULN-06 | Admin token inside the system prompt | CWE-200 | LLM07 | custom Semgrep `secret-in-llm-prompt`, red team SP-* | `prompts.py` (no secrets, canary) |
| VULN-07 | Model tool call passed to `eval()` | CWE-95 | LLM05, LLM06 | Bandit B307, custom Semgrep `llm-output-to-code-execution`, red team AG-* | `tools.py` (`ast` allow-list) |
| VULN-08 | Model output rendered with Jinja2 `autoescape=False` | CWE-79 | LLM05 | Bandit B701, Semgrep, red team OH-* | JSON-only API + `guardrails.check_output` |
| VULN-09 | `debug=True` and a handler that returns tracebacks | CWE-209 | A05 | `test_vuln09_*`, ZAP | generic 500 handler in `api.py` |
| VULN-10 | No input, output or rate limits (`max_tokens=10**6`) | CWE-770 | LLM10 | custom Semgrep `unbounded-llm-output`, red team UC-* | body/question/output caps, `ratelimit.py`, WAF |
| VULN-11 | CORS `*` with credentials | CWE-942 | A05 | Semgrep `wildcard-cors` | no CORS; strict security headers |
| VULN-12 | Binds all interfaces from code | CWE-1327 | A05 | Bandit B104 | bind address set by the container entrypoint only |
| VULN-13 | Container: EOL `python:3.8-slim-buster`, runs as root, outdated pins | CWE-250, CWE-1104 | LLM03 | Trivy, pip-audit, Checkov, hadolint | distroless, non-root, hash-locked deps |
| VULN-14 | Terraform: SSH and app open to the world, `Action "*"`, public IP, IMDSv1, unencrypted disk, public bucket, secret in user data | CWE-284, CWE-311, CWE-798 | A05 | Checkov, Semgrep | `infra/terraform/` |

Run it locally (port 8002, keys `alice123`, `bob123`, `mallory123`):

```bash
docker build -f vulnerable/Dockerfile -t docqa-vulnerable:scan .
docker run --rm -p 127.0.0.1:8002:8000 docqa-vulnerable:scan
```
