import pytest

import main
from conftest import make_token
from test_ingest_lifecycle import finding_id, ingest, report, vuln

OTHER_ID = "pytest-user-b"


@pytest.fixture
def other(client):
    headers = {"Authorization": f"Bearer {make_token(sub=OTHER_ID, email='b@example.com')}"}
    yield headers
    with main.get_driver().session() as session:
        session.run("MATCH (u:User {id: $id}) DETACH DELETE u", id=OTHER_ID).consume()


def ingest_other(client, repo: str, body: dict) -> dict:
    res = client.post(
        "/ingest/trivy",
        params={
            "owner": OTHER_ID,
            "repo_name": repo,
            "repo_url": f"https://git.example.com/{repo}",
            "asset_name": f"{repo}-api",
            "asset_environment": "staging",
            "asset_type": "Docker container",
        },
        json=body,
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_same_names_do_not_merge(client, other, repo):
    ingest(client, repo, report("pyyaml", "requests"))
    ingest_other(client, repo, report("pyyaml"))

    mine = client.get("/findings", params={"status": "all"}).json()
    theirs = client.get("/findings", params={"status": "all"}, headers=other).json()
    mine_ids = {f["vulnerability"]["id"] for f in mine if f["repository"]["name"] == repo}
    their_ids = {f["vulnerability"]["id"] for f in theirs if f["repository"]["name"] == repo}
    assert mine_ids == {finding_id(repo, "pyyaml"), finding_id(repo, "requests")}
    assert their_ids == {finding_id(repo, "pyyaml")}

    mine_asset = next(f["asset"] for f in mine if f["repository"]["name"] == repo)
    their_asset = next(f["asset"] for f in theirs if f["repository"]["name"] == repo)
    assert mine_asset["environment"] == "production"
    assert their_asset["environment"] == "staging"


def test_status_change_does_not_cross_owners(client, other, repo):
    ingest(client, repo, report("pyyaml"))
    ingest_other(client, repo, report("pyyaml"))
    fid = finding_id(repo, "pyyaml")

    res = client.patch(f"/findings/{fid}", json={"status": "false_positive"}, headers=other)
    assert res.status_code == 200
    assert vuln(client, repo, "pyyaml")["status"] == "open"
    theirs = client.get(f"/findings/{fid}", headers=other).json()["vulnerability"]
    assert theirs["status"] == "false_positive"


def test_other_owner_cannot_see_or_change(client, other, repo):
    ingest(client, repo, report("pyyaml"))
    fid = finding_id(repo, "pyyaml")

    assert client.get(f"/findings/{fid}", headers=other).status_code == 404
    res = client.patch(f"/findings/{fid}", json={"status": "resolved"}, headers=other)
    assert res.status_code == 404
    assert vuln(client, repo, "pyyaml")["status"] == "open"

    findings = client.get("/findings", params={"status": "all"}, headers=other).json()
    assert all(f["repository"]["name"] != repo for f in findings)

    assets = client.get("/assets", headers=other).json()
    assert all(not a["asset"]["name"].startswith(repo) for a in assets)

    graph = client.get("/graph", params={"status": "all"}, headers=other).json()
    assert all(repo not in n["id"] for n in graph["nodes"])
    assert all(repo not in link["source"] and repo not in link["target"] for link in graph["links"])

    scans = client.get("/scans", params={"repo": repo}, headers=other).json()
    assert scans == []

    catalog = client.get("/catalog", headers=other).json()
    assert all(entry["repository"]["name"] != repo for entry in catalog)


def test_failing_scans_are_per_owner(client, other, repo):
    res = client.post(
        "/scans/failed",
        json={
            "repo_name": repo,
            "repo_url": f"https://git.example.com/{repo}",
            "scanner": "trivy",
            "error": "Couldn't clone the repository",
        },
    )
    assert res.status_code == 201, res.text

    mine = client.get("/scans/failing").json()
    theirs = client.get("/scans/failing", headers=other).json()
    assert any(f["repository"] == repo for f in mine)
    assert all(f["repository"] != repo for f in theirs)


def test_catalog_is_per_owner(client, other, repo):
    body = {
        "repositories": [
            {
                "name": repo,
                "url": f"https://git.example.com/{repo}",
                "assets": [
                    {"name": f"{repo}-svc", "environment": "production", "type": "Docker container"}
                ],
            }
        ]
    }
    assert client.post("/catalog", json=body).status_code == 200

    mine = {e["repository"]["name"] for e in client.get("/catalog").json()}
    theirs = {e["repository"]["name"] for e in client.get("/catalog", headers=other).json()}
    assert repo in mine
    assert repo not in theirs


def test_discovery_decommission_is_per_owner(client, other, repo):
    def discover(owner: str, names: list[str]) -> dict:
        res = client.post(
            "/assets/discover",
            params={"owner": owner},
            json={
                "source": "docker",
                "assets": [
                    {"name": n, "image": "img", "labels": {"aspm.environment": "production"}}
                    for n in names
                ],
            },
        )
        assert res.status_code == 200, res.text
        return res.json()

    discover(OTHER_ID, [f"{repo}-box"])
    result = discover("pytest-user", [f"{repo}-other"])
    assert f"{repo}-box" not in result["decommissioned"]

    assets = client.get("/assets", headers=other).json()
    box = next(a for a in assets if a["asset"]["name"] == f"{repo}-box")
    assert box["asset"]["status"] == "active"


def test_machine_route_requires_owner(client, monkeypatch, repo):
    monkeypatch.setattr(main, "DEV_OWNER", "")
    res = client.post(
        "/ingest/trivy",
        params={"owner": "", "repo_name": repo, "repo_url": f"https://git.example.com/{repo}"},
        json=report("pyyaml"),
    )
    assert res.status_code == 422


def test_machine_route_needs_api_key(client, repo):
    res = client.post(
        "/ingest/trivy",
        params={"owner": OTHER_ID, "repo_name": repo, "repo_url": f"https://git.example.com/{repo}"},
        json=report("pyyaml"),
        headers={"X-API-Key": "wrong"},
    )
    assert res.status_code == 401
