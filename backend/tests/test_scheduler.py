from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import main
from conftest import TEST_USER_ID

MONDAY_10 = datetime(2030, 1, 7, 10, 30, tzinfo=timezone.utc)
MONDAY_9 = MONDAY_10.replace(hour=9, minute=0)
LONG_AGO = "2000-01-01T00:00:00+00:00"


@pytest.fixture
def repository(client):
    name = f"pytest-sched-{uuid4().hex[:10]}"
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


def run(query, **params):
    with main.get_driver().session() as session:
        session.run(query, owner=TEST_USER_ID, **params).consume()


def jobs(name):
    with main.get_driver().session() as session:
        return [
            record["j"]
            for record in session.run(
                "MATCH (:Repository {owner: $owner, name: $name})-[:HAS_JOB]->(j:ScanJob) "
                "RETURN j { .* } AS j ORDER BY j.requested_at",
                owner=TEST_USER_ID,
                name=name,
            )
        ]


def scheduled(name, set_at=LONG_AGO):
    run(
        "MATCH (r:Repository {owner: $owner, name: $name}) "
        "SET r.last_scanned_at = $long_ago, r.schedule_weekday = 0, r.schedule_hour = 9, "
        "r.schedule_set_at = $set_at",
        name=name,
        long_ago=LONG_AGO,
        set_at=set_at,
    )


def past_job(name, status, requested_at):
    run(
        "MATCH (r:Repository {owner: $owner, name: $name}) "
        "CREATE (r)-[:HAS_JOB]->(:ScanJob {id: $id, owner: $owner, repository_name: $name, "
        "status: $status, requested_at: $at})",
        name=name,
        id=uuid4().hex,
        status=status,
        at=requested_at,
    )


def tick(now=MONDAY_10):
    return main.schedule_scans(now=now, owner=TEST_USER_ID)


def test_last_slot():
    assert main._last_slot(MONDAY_10, 0, 9) == MONDAY_9
    assert main._last_slot(MONDAY_10, 0, 11) == MONDAY_9.replace(hour=11) - timedelta(days=7)
    assert main._last_slot(MONDAY_10, 6, 23) == datetime(2030, 1, 6, 23, tzinfo=timezone.utc)
    assert main._last_slot(MONDAY_10, 2, 0) == datetime(2030, 1, 2, 0, tzinfo=timezone.utc)


def test_new_selected_repository_gets_one_first_scan(client, repository):
    first = tick()
    second = tick()

    assert first["first"] >= 1
    assert second["first"] == 0
    [job] = jobs(repository)
    assert job["trigger"] == "first"
    assert job["requested_by"] == "scheduler"
    assert job["status"] == "queued"
    assert job["scanners"] == ["trivy", "semgrep"]


def test_no_first_scan_for_unselected_revoked_or_scanned(client, repository):
    for change in ("r.selected = false", "r.access_revoked = true", "r.last_scanned_at = $long_ago"):
        run(
            "MATCH (r:Repository {owner: $owner, name: $name}) "
            "SET r.selected = true, r.access_revoked = false, r.last_scanned_at = null",
            name=repository,
        )
        run(
            f"MATCH (r:Repository {{owner: $owner, name: $name}}) SET {change}",
            name=repository,
            long_ago=LONG_AGO,
        )

        tick()

        assert jobs(repository) == [], change


def test_due_schedule_is_queued_at_the_slot_time(client, repository):
    scheduled(repository)
    past_job(repository, "done", (MONDAY_9 - timedelta(days=7)).isoformat())

    result = tick()

    assert result["schedule"] == 1
    job = jobs(repository)[-1]
    assert job["trigger"] == "schedule"
    assert job["requested_at"] == MONDAY_9.isoformat()


def test_schedule_not_due_before_its_hour(client, repository):
    scheduled(repository)
    past_job(repository, "done", (MONDAY_9 - timedelta(days=7)).isoformat())

    tick(now=MONDAY_9 - timedelta(minutes=1))

    assert len(jobs(repository)) == 1


def test_schedule_skips_slot_already_requested(client, repository):
    scheduled(repository)
    past_job(repository, "failed", (MONDAY_9 + timedelta(minutes=5)).isoformat())

    tick()

    assert len(jobs(repository)) == 1


def test_schedule_respects_cooldown(client, repository):
    scheduled(repository)
    past_job(repository, "done", (MONDAY_9 - timedelta(days=3)).isoformat())

    tick()

    assert len(jobs(repository)) == 1


def test_schedule_does_not_catch_up_on_slot_before_it_was_set(client, repository):
    scheduled(repository, set_at=(MONDAY_9 + timedelta(minutes=10)).isoformat())

    tick()

    assert jobs(repository) == []


def test_schedule_waits_while_a_job_is_open(client, repository):
    scheduled(repository)
    past_job(repository, "queued", LONG_AGO)

    tick()

    assert len(jobs(repository)) == 1


def test_put_schedule_sets_and_clears(client, repository):
    response = client.put(f"/repositories/{repository}/schedule", json={"weekday": 4, "hour": 18})

    assert response.status_code == 200
    stored = response.json()["repository"]
    assert stored["schedule_weekday"] == 4
    assert stored["schedule_hour"] == 18
    assert stored["schedule_set_at"]

    cleared = client.put(
        f"/repositories/{repository}/schedule", json={"weekday": None, "hour": None}
    ).json()["repository"]

    assert "schedule_weekday" not in cleared
    assert "schedule_set_at" not in cleared


def test_put_schedule_validates(client, repository):
    path = f"/repositories/{repository}/schedule"

    assert client.put(path, json={"weekday": 7, "hour": 9}).status_code == 422
    assert client.put(path, json={"weekday": 1, "hour": 24}).status_code == 422
    assert client.put(path, json={"weekday": 1}).status_code == 422
    assert client.put(f"/repositories/{repository}-nope/schedule", json={"weekday": 1, "hour": 9}).status_code == 404
    assert client.put(path, json={"weekday": 1, "hour": 9}, headers={"Authorization": ""}).status_code == 401
