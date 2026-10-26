from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import main
from conftest import TEST_USER_ID


@pytest.fixture
def repository(client):
    name = f"pytest-jobs-{uuid4().hex[:10]}"
    client.post("/repositories", json={"name": name, "url": f"https://github.com/pytest/{name}"})
    yield name
    with main.get_driver().session() as session:
        session.run(
            """
            MATCH (n) WHERE (n:Repository AND n.name = $name)
                         OR (n:ScanJob AND n.repository_name = $name)
            DETACH DELETE n
            """,
            name=name,
        ).consume()


def finish(job_id, status, days_ago=0):
    requested = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    with main.get_driver().session() as session:
        session.run(
            """
            MATCH (j:ScanJob {id: $id})
            SET j.status = $status, j.requested_at = $requested
            REMOVE j.active_repository
            """,
            id=job_id,
            status=status,
            requested=requested,
        ).consume()


def test_scan_now_queues_a_job(client, repository):
    response = client.post("/scans/run", json={"repository": repository.upper()})

    assert response.status_code == 201
    job = response.json()["job"]
    assert job["repository_name"] == repository
    assert job["status"] == "queued"
    assert job["scanners"] == ["trivy", "semgrep"]
    assert job["requested_by"] == TEST_USER_ID
    with main.get_driver().session() as session:
        stored = session.run(
            "MATCH (r:Repository {owner: $owner, name: $name})-[:HAS_JOB]->(j:ScanJob {id: $id}) "
            "RETURN r.last_scan_requested_at AS at, j.owner AS owner",
            owner=TEST_USER_ID,
            name=repository,
            id=job["id"],
        ).single()
    assert stored["at"] == job["requested_at"]
    assert stored["owner"] == TEST_USER_ID


def test_scan_now_takes_chosen_scanners(client, repository):
    response = client.post(
        "/scans/run", json={"repository": repository, "scanners": ["semgrep", "semgrep"]}
    )

    assert response.json()["job"]["scanners"] == ["semgrep"]


def test_second_scan_while_queued_is_a_conflict(client, repository):
    first = client.post("/scans/run", json={"repository": repository})

    second = client.post("/scans/run", json={"repository": repository})

    assert first.status_code == 201
    assert second.status_code == 409


def test_done_scan_starts_the_cooldown(client, repository):
    job = client.post("/scans/run", json={"repository": repository}).json()["job"]
    finish(job["id"], "done", days_ago=1)

    response = client.post("/scans/run", json={"repository": repository})

    assert response.status_code == 429
    next_allowed = datetime.fromisoformat(response.json()["detail"]["next_allowed_at"])
    expected = datetime.fromisoformat(job["requested_at"]) + timedelta(days=main.SCAN_COOLDOWN_DAYS - 1)
    assert abs((next_allowed - expected).total_seconds()) < 60
    assert int(response.headers["Retry-After"]) > 0


def test_scan_allowed_after_cooldown(client, repository):
    job = client.post("/scans/run", json={"repository": repository}).json()["job"]
    finish(job["id"], "done", days_ago=main.SCAN_COOLDOWN_DAYS + 1)

    assert client.post("/scans/run", json={"repository": repository}).status_code == 201


def test_failed_scan_does_not_use_up_the_week(client, repository):
    job = client.post("/scans/run", json={"repository": repository}).json()["job"]
    finish(job["id"], "failed")

    assert client.post("/scans/run", json={"repository": repository}).status_code == 201


def test_scan_now_unknown_or_foreign_repository_is_404(client, repository):
    with main.get_driver().session() as session:
        session.run(
            "CREATE (:Repository {owner: 'someone-else', name: $name})", name=f"{repository}-x"
        ).consume()
    try:
        missing = client.post("/scans/run", json={"repository": f"{repository}-nope"})
        foreign = client.post("/scans/run", json={"repository": f"{repository}-x"})
    finally:
        with main.get_driver().session() as session:
            session.run(
                "MATCH (r:Repository {owner: 'someone-else', name: $name}) DETACH DELETE r",
                name=f"{repository}-x",
            ).consume()

    assert missing.status_code == 404
    assert foreign.status_code == 404


def test_scan_now_revoked_repository_is_a_conflict(client, repository):
    with main.get_driver().session() as session:
        session.run(
            "MATCH (r:Repository {owner: $owner, name: $name}) SET r.access_revoked = true",
            owner=TEST_USER_ID,
            name=repository,
        ).consume()

    assert client.post("/scans/run", json={"repository": repository}).status_code == 409


def test_scan_now_rejects_unknown_scanner(client, repository):
    response = client.post("/scans/run", json={"repository": repository, "scanners": ["nmap"]})

    assert response.status_code == 422


def test_scan_now_requires_login(client, repository):
    response = client.post(
        "/scans/run", json={"repository": repository}, headers={"Authorization": ""}
    )

    assert response.status_code == 401
