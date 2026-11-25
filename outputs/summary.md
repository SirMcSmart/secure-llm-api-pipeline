| Stage | Scanner | Baseline (vulnerable/) | Hardened |
|---|---|---|---|
| SAST | Semgrep (p/python, p/owasp-top-ten, custom LLM rules) | 5 error, 8 warning, 0 info | 0 error, 0 warning, 0 info |
| SAST | Bandit | 5 high, 3 medium, 2 low | 0 high, 0 medium, 0 low |
| SCA | pip-audit (Python dependencies) | 4 vulnerable packages, 29 vulnerabilities | 0 vulnerable packages, 0 vulnerabilities |
| SCA | Trivy (container image) | 2 critical, 48 high, 67 medium, 32 low, 22 high critical fixable | 0 critical, 0 high, 0 medium, 0 low, 0 high critical fixable |
| Secrets | gitleaks | 1 findings | 0 findings |
| IaC | Checkov (Terraform) | 28 failed, 16 passed, 0 skipped | 0 failed, 188 passed, 9 skipped |
| IaC | terraform validate | True valid, 0 errors | True valid, 0 errors |
| Container | Checkov (Dockerfile) | 2 failed, 28 passed | 0 failed, 36 passed |
| Container | hadolint | 0 error, 1 warning, 0 info | 0 error, 0 warning, 0 info |
| CI/CD | Checkov (GitHub Actions workflow) | not run | 0 failed, 164 passed |
| DAST | OWASP ZAP baseline (passive) | 0 high, 0 medium, 2 low, 1 informational | 0 high, 0 medium, 0 low, 1 informational |
| DAST | OWASP ZAP API scan (active, OpenAPI) | 1 high, 2 medium, 8 low, 2 informational | 0 high, 0 medium, 0 low, 2 informational |
| LLM red team | Prompt-injection / jailbreak corpus | 23 of 23 attacks succeeded | 0 of 23 attacks succeeded |

**Security gate (hardened): PASSED**
