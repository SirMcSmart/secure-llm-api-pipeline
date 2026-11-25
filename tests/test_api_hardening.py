"""HTTP-level hardening: headers, error handling, limits, exposed surface."""

from fastapi.testclient import TestClient

from docqa.api import create_app
from docqa.config import Settings
from redteam_lib import hardened


def test_security_headers_on_every_response(hard):
    for r in (hard.client.get("/health"), hard.client.get("/v1/documents"), hard.client.get("/nope")):
        assert r.headers["content-security-policy"].startswith("default-src 'none'")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["cache-control"] == "no-store"
        assert "x-request-id" in r.headers


def test_answers_are_json_never_html(hard):
    r = hard.client.post("/v1/ask", headers=hard.headers("alice"), json={"question": "How many days of PTO?"})
    assert r.headers["content-type"].startswith("application/json")


def test_api_docs_disabled_by_default(hard):
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert hard.client.get(path).status_code == 404


def test_unknown_fields_rejected(hard):
    r = hard.client.post("/v1/ask", headers=hard.headers("alice"), json={"question": "x", "system": "evil"})
    assert r.status_code == 422


def test_oversized_body_rejected(hard):
    r = hard.client.post("/v1/ask", headers=hard.headers("alice"), content=b"{" + b" " * 20000 + b"}")
    assert r.status_code == 413


def test_question_length_limit(hard):
    r = hard.client.post("/v1/ask", headers=hard.headers("alice"), json={"question": "a" * 501})
    assert r.status_code == 422


def test_rate_limit_per_user():
    target = hardened(rate_limit_per_minute=3)
    codes = [target.client.get("/v1/documents", headers=target.headers("alice")).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    # another user has their own bucket
    assert target.client.get("/v1/documents", headers=target.headers("bob")).status_code == 200


def test_internal_errors_do_not_leak_details():
    class ExplodingLLM:
        name = "boom"

        def complete(self, system, user, max_tokens):
            raise RuntimeError("secret internal detail /etc/app/config")

    from docqa.auth import hash_key

    app = create_app(Settings(api_key_hashes={hash_key("k"): "alice"}), llm=ExplodingLLM())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/v1/ask", headers={"Authorization": "Bearer k"}, json={"question": "PTO days?"})
    assert r.status_code == 500
    assert "secret internal detail" not in r.text and "Traceback" not in r.text
    assert r.json()["detail"] == "internal error"
