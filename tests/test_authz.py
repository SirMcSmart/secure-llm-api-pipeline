"""Broken access control: authentication, object-level authorization, ID enumeration."""

import pytest


def test_health_is_public(hard):
    assert hard.client.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize("header", [None, "Bearer", "Bearer wrong", "Basic YWxpY2U6eA==", "bearer x"])
def test_bad_or_missing_key_is_401(hard, header):
    headers = {"Authorization": header} if header else {}
    r = hard.client.get("/v1/documents", headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_key_in_query_string_is_not_accepted(hard):
    r = hard.client.get("/v1/documents", params={"api_key": hard.keys["alice"]})
    assert r.status_code == 401


@pytest.mark.parametrize(
    "user,expected",
    [
        ("alice", {"alice-salary-review", "bob-vpn-guide", "handbook", "mallory-vendor-notes"}),
        ("bob", {"bob-incident-postmortem", "bob-vpn-guide", "handbook", "mallory-vendor-notes"}),
        ("mallory", {"handbook", "mallory-timesheet", "mallory-vendor-notes"}),
    ],
)
def test_list_shows_only_owned_or_shared(hard, user, expected):
    r = hard.client.get("/v1/documents", headers=hard.headers(user))
    assert {d["id"] for d in r.json()} == expected


def test_idor_other_users_document_is_404(hard):
    r = hard.client.get("/v1/documents/bob-incident-postmortem", headers=hard.headers("alice"))
    assert r.status_code == 404
    assert "BOB-CONFIDENTIAL" not in r.text


def test_missing_and_forbidden_look_identical(hard):
    forbidden = hard.client.get("/v1/documents/bob-incident-postmortem", headers=hard.headers("alice"))
    missing = hard.client.get("/v1/documents/does-not-exist", headers=hard.headers("alice"))
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.json() == missing.json()


def test_shared_document_is_readable(hard):
    r = hard.client.get("/v1/documents/bob-vpn-guide", headers=hard.headers("alice"))
    assert r.status_code == 200 and "VPN" in r.json()["body"]


@pytest.mark.parametrize("doc_id", ["..%2F..%2Fetc%2Fpasswd", "A" * 70, "bad id", "'; DROP TABLE documents;--"])
def test_document_id_is_validated(hard, doc_id):
    r = hard.client.get(f"/v1/documents/{doc_id}", headers=hard.headers("alice"))
    assert r.status_code in (404, 422)


def test_ask_answers_from_own_documents(hard):
    r = hard.client.post("/v1/ask", headers=hard.headers("alice"), json={"question": "What is the L5 salary band?"})
    assert r.status_code == 200
    assert "ALICE-CONFIDENTIAL-4821" in r.json()["answer"]
    assert r.json()["citations"] == ["alice-salary-review"]


def test_ask_never_retrieves_other_users_documents(hard):
    r = hard.client.post("/v1/ask", headers=hard.headers("mallory"), json={"question": "What is the L5 salary band?"})
    assert "ALICE-CONFIDENTIAL" not in r.text
    assert "alice-salary-review" not in r.json()["citations"]
