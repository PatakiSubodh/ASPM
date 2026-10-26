from uuid import uuid4

import pytest

import github
import main
from conftest import TEST_USER_ID
from test_github_sync import PREFIX, granted, installation, item  # noqa: F401

OLD = "2000-01-01T00:00:00+00:00"


@pytest.fixture(autouse=True)
def clean_jobs():
    yield
    with main.get_driver().session() as session:
        session.run(
            "MATCH (j:ScanJob) WHERE j.repository_name STARTS WITH 'pytest-' DETACH DELETE j"
        ).consume()


@pytest.fixture
def repository(client):
    name = f"pytest-claim-{uuid4().hex[:10]}"
    client.post("/repositories", json={"name": name, "url": f"https://github.com/pytest/{name}"})
    yield name
    with main.get_driver().session() as session:
        session.run(
            "MATCH (n) WHERE (n:Repository AND n.name = $name) OR (n:Scan AND n.id STARTS WITH $name) "
            "DETACH DELETE n",
            name=name,
        ).consume()


def queue(client, name, requested_at=OLD):
    job = client.post("/scans/run", json={"repository": name}).json()["job"]
    with main.get_driver().session() as session:
        session.run(
            "MATCH (j:ScanJob {id: $id}) SET j.requested_at = $at", id=job["id"], at=requested_at
        ).consume()
    return job


def claim(client):
    response = client.post("/jobs/claim")
    assert response.status_code == 200
    return response.json()


def job_node(job_id):
    with main.get_driver().session() as session:
        return session.run("MATCH (j:ScanJob {id: $id}) RETURN j { .* } AS j", id=job_id).single()["j"]


def test_claim_returns_oldest_queued_job_with_repository(client, repository):
    job = queue(client, repository)

    claimed = claim(client)

    assert claimed["job"]["id"] == job["id"]
    assert claimed["job"]["status"] == "claimed"
    assert claimed["owner"] == TEST_USER_ID
    assert claimed["claim_id"]
    assert claimed["lease_expires_at"] > main._now()
    assert claimed["repository"]["name"] == repository
    assert claimed["repository"]["url"] == f"https://github.com/pytest/{repository}"
    assert claimed["token"] is None
    assert job_node(job["id"])["attempts"] == 1


def test_claimed_job_is_not_handed_out_twice(client, repository):
    job = queue(client, repository)
    claim(client)

    second = claim(client)

    assert second["job"] is None or second["job"]["id"] != job["id"]


def test_expired_lease_is_claimed_again_and_old_claim_is_rejected(client, repository):
    job = queue(client, repository)
    first = claim(client)
    with main.get_driver().session() as session:
        session.run(
            "MATCH (j:ScanJob {id: $id}) SET j.lease_expires_at = $past", id=job["id"], past=OLD
        ).consume()

    second = claim(client)
    stale = client.post(
        f"/jobs/{job['id']}/complete", json={"claim_id": first["claim_id"], "status": "done"}
    )

    assert second["job"]["id"] == job["id"]
    assert second["claim_id"] != first["claim_id"]
    assert job_node(job["id"])["attempts"] == 2
    assert stale.status_code == 409


def test_complete_done_links_own_scans_and_starts_cooldown(client, repository):
    job = queue(client, repository)
    claimed = claim(client)
    own, foreign = f"{repository}-own", f"{repository}-foreign"
    with main.get_driver().session() as session:
        session.run(
            "CREATE (:Scan {id: $own, owner: $owner}), (:Scan {id: $foreign, owner: 'someone-else'})",
            own=own,
            foreign=foreign,
            owner=TEST_USER_ID,
        ).consume()

    response = client.post(
        f"/jobs/{job['id']}/complete",
        json={"claim_id": claimed["claim_id"], "status": "done", "scan_ids": [own, foreign]},
    )

    assert response.status_code == 200
    assert response.json()["job"]["status"] == "done"
    assert response.json()["linked"] == 1
    stored = job_node(job["id"])
    assert "active_repository" not in stored
    assert "claim_id" not in stored
    with main.get_driver().session() as session:
        session.run(
            "MATCH (j:ScanJob {id: $id}) SET j.requested_at = $now", id=job["id"], now=main._now()
        ).consume()
    assert client.post("/scans/run", json={"repository": repository}).status_code == 429


def test_complete_failed_needs_error_and_frees_the_repository(client, repository):
    job = queue(client, repository)
    claimed = claim(client)

    missing_error = client.post(
        f"/jobs/{job['id']}/complete", json={"claim_id": claimed["claim_id"], "status": "failed"}
    )
    failed = client.post(
        f"/jobs/{job['id']}/complete",
        json={"claim_id": claimed["claim_id"], "status": "failed", "error": "clone failed"},
    )

    assert missing_error.status_code == 422
    assert failed.status_code == 200
    assert job_node(job["id"])["error"] == "clone failed"
    assert client.post("/scans/run", json={"repository": repository}).status_code == 201


def test_complete_unknown_job_is_404_and_unclaimed_is_409(client, repository):
    job = client.post("/scans/run", json={"repository": repository}).json()["job"]

    unknown = client.post("/jobs/nope/complete", json={"claim_id": "x", "status": "done"})
    unclaimed = client.post(f"/jobs/{job['id']}/complete", json={"claim_id": "x", "status": "done"})

    assert unknown.status_code == 404
    assert unclaimed.status_code == 409


def test_revoked_repository_job_is_failed_at_claim(client, repository):
    job = queue(client, repository)
    with main.get_driver().session() as session:
        session.run(
            "MATCH (r:Repository {owner: $owner, name: $name}) SET r.access_revoked = true",
            owner=TEST_USER_ID,
            name=repository,
        ).consume()

    claimed = claim(client)

    assert claimed["job"] is None or claimed["job"]["id"] != job["id"]
    stored = job_node(job["id"])
    assert stored["status"] == "failed"
    assert stored["error"] == "Repository access was revoked on GitHub"


def github_job(client, monkeypatch, installation):
    create, created = installation
    create("selected")
    granted(monkeypatch, [item(42, "api")])
    client.post("/github/repositories/refresh")
    return queue(client, f"{PREFIX}/api"), created["id"]


def test_github_job_gets_a_token_scoped_to_its_repository(client, monkeypatch, installation):
    job, installation_id = github_job(client, monkeypatch, installation)
    calls = []

    def token(installation_id, repository_ids=None):
        calls.append((installation_id, repository_ids))
        return {"token": "ghs_job", "expires_at": "2099-01-01T00:00:00Z"}

    monkeypatch.setattr(github, "installation_token", token)

    claimed = claim(client)

    assert claimed["job"]["id"] == job["id"]
    assert claimed["token"] == "ghs_job"
    assert claimed["token_expires_at"] == "2099-01-01T00:00:00Z"
    assert claimed["repository"]["full_name"] == f"{PREFIX}/api"
    assert calls == [(installation_id, [42])]


def test_uninstalled_app_fails_the_job_and_marks_removed(client, monkeypatch, installation):
    job, installation_id = github_job(client, monkeypatch, installation)

    def gone(installation_id, repository_ids=None):
        raise github.GitHubError(404, "Not Found")

    monkeypatch.setattr(github, "installation_token", gone)

    claimed = claim(client)

    assert claimed["job"] is None or claimed["job"]["id"] != job["id"]
    assert job_node(job["id"])["status"] == "failed"
    with main.get_driver().session() as session:
        status = session.run(
            "MATCH (i:GitHubInstallation {id: $id}) RETURN i.status AS s", id=installation_id
        ).single()["s"]
    assert status == "removed"


def test_github_outage_puts_the_job_back(client, monkeypatch, installation):
    job, _ = github_job(client, monkeypatch, installation)

    def down(installation_id, repository_ids=None):
        raise github.GitHubError(502, "Bad Gateway")

    monkeypatch.setattr(github, "installation_token", down)

    response = client.post("/jobs/claim")

    assert response.status_code == 502
    stored = job_node(job["id"])
    assert stored["status"] == "queued"
    assert "claim_id" not in stored


def test_job_routes_require_api_key(client, repository):
    job = client.post("/scans/run", json={"repository": repository}).json()["job"]

    claimed = client.post("/jobs/claim", headers={"X-API-Key": ""})
    completed = client.post(
        f"/jobs/{job['id']}/complete",
        json={"claim_id": "x", "status": "done"},
        headers={"X-API-Key": "wrong"},
    )

    assert claimed.status_code == 401
    assert completed.status_code == 401
