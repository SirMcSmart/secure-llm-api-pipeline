"""SQL injection (CWE-89) against the title search."""

import pytest

PAYLOADS = ["' OR 1=1 --", "%' UNION SELECT id, body, owner FROM documents --", "%", "_", "\\"]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_search_payloads_are_data_not_sql(hard, payload):
    r = hard.client.get("/v1/search", params={"q": payload}, headers=hard.headers("mallory"))
    assert r.status_code == 200
    assert r.json() == []  # no title contains these strings literally


def test_search_is_scoped_to_caller(hard):
    r = hard.client.get("/v1/search", params={"q": "confidential"}, headers=hard.headers("mallory"))
    assert r.json() == []
    r = hard.client.get("/v1/search", params={"q": "confidential"}, headers=hard.headers("bob"))
    assert [d["id"] for d in r.json()] == ["bob-incident-postmortem"]


def test_search_query_length_is_bounded(hard):
    r = hard.client.get("/v1/search", params={"q": "a" * 101}, headers=hard.headers("bob"))
    assert r.status_code == 422
