import time

import pytest

import main
from conftest import TEST_USER_ID, make_token
from test_ingest_lifecycle import finding_id, ingest, report


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_valid_token_reads_and_saves_user(client):
    assert client.get("/findings").status_code == 200
    with main.get_driver().session() as session:
        user = session.run("MATCH (u:User {id: $id}) RETURN u { .* } AS u", id=TEST_USER_ID).single()["u"]
    assert user["email"] == "pytest@example.com"
    assert user["provider"] == "email"
    assert user["first_seen"] and user["last_seen"]


def test_missing_token(client):
    assert client.get("/findings", headers={"Authorization": ""}).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(time.time()) - 60},
        {"aud": "anon"},
        {"iss": "https://someone-else.supabase.co/auth/v1"},
    ],
    ids=["expired", "wrong-audience", "wrong-issuer"],
)
def test_rejected_tokens(client, overrides):
    assert client.get("/findings", headers=bearer(make_token(**overrides))).status_code == 401


def test_api_key_alone_cannot_read(client):
    assert client.get("/assets", headers={"Authorization": ""}).status_code == 401


def test_token_alone_cannot_ingest(client):
    assert client.post("/scans/failed", json={}, headers={"X-API-Key": ""}).status_code == 401


def test_patch_records_user(client, repo):
    ingest(client, repo, report("jinja2"))
    target = finding_id(repo, "jinja2")

    body = client.patch(f"/findings/{target}", json={"status": "in_progress"}).json()["vulnerability"]
    assert body["status_changed_by"] == "pytest@example.com"
    assert body["status_changed_by_id"] == TEST_USER_ID
