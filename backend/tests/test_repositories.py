import pytest

import main
from conftest import make_token
from test_ingest_lifecycle import finding_id, report

OTHER_ID = "pytest-user-b"


@pytest.fixture
def other(client):
    headers = {"Authorization": f"Bearer {make_token(sub=OTHER_ID, email='b@example.com')}"}
    yield headers
    with main.get_driver().session() as session:
        session.run("MATCH (u:User {id: $id}) DETACH DELETE u", id=OTHER_ID).consume()


def create_repo(client, repo: str, **headers) -> dict:
    res = client.post(
        "/repositories",
        json={"name": repo, "url": f"https://git.example.com/{repo}"},
        **headers,
    )
    assert res.status_code == 201, res.text
    return res.json()["repository"]


def create_asset(client, name: str, **headers) -> dict:
    res = client.post(
        "/assets",
        json={"name": name, "environment": "production", "type": "Docker container"},
        **headers,
    )
    assert res.status_code == 201, res.text
    return res.json()["asset"]


def scan_without_asset(client, repo: str) -> None:
    res = client.post(
        "/ingest/trivy",
        params={"repo_name": repo, "repo_url": f"https://git.example.com/{repo}"},
        json=report("pyyaml"),
    )
    assert res.status_code == 201, res.text


def finding_assets(client, repo: str) -> list[str]:
    res = client.get(f"/findings/{finding_id(repo, 'pyyaml')}")
    assert res.status_code == 200, res.text
    return sorted(a["name"] for a in res.json()["assets"])


def test_create_and_list_repository(client, repo):
    created = create_repo(client, repo.upper())
    assert created["name"] == repo
    assert created["selected"] is True
    assert created["source"] == "manual"

    entry = next(e for e in client.get("/repositories").json() if e["repository"]["name"] == repo)
    assert entry["assets"] == []
    assert entry["open_total"] == 0


def test_create_repository_rejects_duplicates_and_bad_input(client, repo):
    create_repo(client, repo)
    again = client.post(
        "/repositories", json={"name": repo, "url": f"https://git.example.com/{repo}"}
    )
    assert again.status_code == 409

    bad_url = client.post("/repositories", json={"name": f"{repo}-x", "url": "file:///etc"})
    assert bad_url.status_code == 422
    blank = client.post("/repositories", json={"name": "  ", "url": "https://git.example.com/x"})
    assert blank.status_code == 422


def test_update_repository(client, repo):
    create_repo(client, repo)

    res = client.patch(f"/repositories/{repo}", json={"selected": False, "branch": " dev "})
    assert res.status_code == 200, res.text
    assert res.json()["repository"]["selected"] is False
    assert res.json()["repository"]["branch"] == "dev"

    cleared = client.patch(f"/repositories/{repo}", json={"branch": None})
    assert cleared.status_code == 200, cleared.text
    assert "branch" not in cleared.json()["repository"]

    assert client.patch(f"/repositories/{repo}", json={}).status_code == 422
    assert client.patch(f"/repositories/{repo}", json={"selected": None}).status_code == 422
    assert client.patch(f"/repositories/{repo}-nope", json={"selected": True}).status_code == 404


def test_repository_from_scan_is_selected_by_default(client, repo):
    scan_without_asset(client, repo)
    entry = next(e for e in client.get("/repositories").json() if e["repository"]["name"] == repo)
    assert entry["repository"]["selected"] is True
    assert entry["open_total"] == 1


def test_asset_crud(client, repo):
    name = f"{repo}-svc"
    created = create_asset(client, name.upper())
    assert created["name"] == name
    assert created["source"] == "manual"
    assert created["internet_facing"] is False

    dup = client.post(
        "/assets", json={"name": name, "environment": "staging", "type": "Docker container"}
    )
    assert dup.status_code == 409

    res = client.patch(f"/assets/{name}", json={"environment": "staging", "internet_facing": True})
    assert res.status_code == 200, res.text
    assert res.json()["asset"]["environment"] == "staging"
    assert res.json()["asset"]["internet_facing"] is True
    assert res.json()["asset"]["type"] == "Docker container"

    assert client.patch(f"/assets/{name}", json={}).status_code == 422
    assert client.patch(f"/assets/{name}", json={"environment": None}).status_code == 422
    assert client.patch(f"/assets/{name}-nope", json={"type": "VM"}).status_code == 404

    listed = {a["asset"]["name"] for a in client.get("/assets").json()}
    assert name in listed
    assert client.delete(f"/assets/{name}").status_code == 204
    assert client.delete(f"/assets/{name}").status_code == 404
    listed = {a["asset"]["name"] for a in client.get("/assets").json()}
    assert name not in listed


def test_set_repository_assets_backfills_and_replaces(client, repo):
    first, second = f"{repo}-one", f"{repo}-two"
    create_asset(client, first)
    create_asset(client, second)
    scan_without_asset(client, repo)
    assert finding_assets(client, repo) == []

    res = client.put(f"/repositories/{repo}/assets", json={"assets": [first.upper(), first]})
    assert res.status_code == 200, res.text
    assert res.json()["assets"] == [first]
    assert (res.json()["linked"], res.json()["unlinked"], res.json()["backfilled"]) == (1, 0, 1)
    assert finding_assets(client, repo) == [first]

    res = client.put(f"/repositories/{repo}/assets", json={"assets": [second]})
    assert res.status_code == 200, res.text
    assert (res.json()["linked"], res.json()["unlinked"], res.json()["backfilled"]) == (1, 1, 1)
    assert finding_assets(client, repo) == [second]

    entry = next(e for e in client.get("/repositories").json() if e["repository"]["name"] == repo)
    assert [a["name"] for a in entry["assets"]] == [second]

    res = client.put(f"/repositories/{repo}/assets", json={"assets": []})
    assert res.status_code == 200, res.text
    assert res.json()["unlinked"] == 1
    assert finding_assets(client, repo) == []


def test_set_repository_assets_rejects_unknown(client, repo):
    create_repo(client, repo)
    res = client.put(f"/repositories/{repo}/assets", json={"assets": [f"{repo}-ghost"]})
    assert res.status_code == 422
    assert f"{repo}-ghost" in res.json()["detail"]
    assert client.put(f"/repositories/{repo}-nope/assets", json={"assets": []}).status_code == 404


def test_deleting_asset_removes_links(client, repo):
    name = f"{repo}-svc"
    create_asset(client, name)
    scan_without_asset(client, repo)
    client.put(f"/repositories/{repo}/assets", json={"assets": [name]})
    assert finding_assets(client, repo) == [name]

    assert client.delete(f"/assets/{name}").status_code == 204
    assert finding_assets(client, repo) == []


def test_other_owner_cannot_see_or_change(client, other, repo):
    name = f"{repo}-svc"
    create_repo(client, repo)
    create_asset(client, name)

    theirs = client.get("/repositories", headers=other).json()
    assert all(e["repository"]["name"] != repo for e in theirs)
    assets = client.get("/assets", headers=other).json()
    assert all(a["asset"]["name"] != name for a in assets)

    assert client.patch(f"/repositories/{repo}", json={"selected": False}, headers=other).status_code == 404
    assert client.put(f"/repositories/{repo}/assets", json={"assets": []}, headers=other).status_code == 404
    assert client.patch(f"/assets/{name}", json={"type": "VM"}, headers=other).status_code == 404
    assert client.delete(f"/assets/{name}", headers=other).status_code == 404

    mine = next(e for e in client.get("/repositories").json() if e["repository"]["name"] == repo)
    assert mine["repository"]["selected"] is True
    kept = next(a for a in client.get("/assets").json() if a["asset"]["name"] == name)
    assert kept["asset"]["type"] == "Docker container"


def test_other_owner_cannot_link_foreign_asset(client, other, repo):
    name = f"{repo}-svc"
    create_asset(client, name)
    create_repo(client, repo, headers=other)

    res = client.put(f"/repositories/{repo}/assets", json={"assets": [name]}, headers=other)
    assert res.status_code == 422
    assert name in res.json()["detail"]


def test_same_names_do_not_collide_across_owners(client, other, repo):
    name = f"{repo}-svc"
    create_repo(client, repo)
    create_repo(client, repo, headers=other)
    create_asset(client, name)
    create_asset(client, name, headers=other)

    res = client.put(f"/repositories/{repo}/assets", json={"assets": [name]}, headers=other)
    assert res.status_code == 200, res.text

    mine = next(e for e in client.get("/repositories").json() if e["repository"]["name"] == repo)
    theirs = next(
        e for e in client.get("/repositories", headers=other).json() if e["repository"]["name"] == repo
    )
    assert mine["assets"] == []
    assert [a["name"] for a in theirs["assets"]] == [name]


def test_routes_need_a_signed_in_user(client):
    anonymous = {"Authorization": ""}
    assert client.get("/repositories", headers=anonymous).status_code == 401
    assert client.post("/repositories", json={}, headers=anonymous).status_code == 401
    assert client.put("/repositories/x/assets", json={}, headers=anonymous).status_code == 401
    assert client.post("/assets", json={}, headers=anonymous).status_code == 401
    assert client.delete("/assets/x", headers=anonymous).status_code == 401
