from urllib.parse import quote
from uuid import uuid4

import pytest

import github
import main
from conftest import TEST_USER_ID

PREFIX = "pytest-sync"


@pytest.fixture
def installation(client, monkeypatch):
    installation_id = int(uuid4().int % 10**9) + 10**9
    created = {"id": installation_id, "selection": "selected"}

    def create(selection):
        with main.get_driver().session() as session:
            session.run(
                """
                MERGE (u:User {id: $owner})
                CREATE (u)-[:HAS_INSTALLATION]->(:GitHubInstallation {
                  id: $id, owner: $owner, status: 'active', repository_selection: $selection
                })
                """,
                owner=TEST_USER_ID,
                id=installation_id,
                selection=selection,
            ).consume()
        created["selection"] = selection

    yield create, created
    with main.get_driver().session() as session:
        session.run("MATCH (i:GitHubInstallation {id: $id}) DETACH DELETE i", id=installation_id).consume()
        session.run(
            "MATCH (r:Repository) WHERE r.name STARTS WITH $prefix DETACH DELETE r",
            prefix=PREFIX,
        ).consume()


def granted(monkeypatch, items):
    monkeypatch.setattr(github, "installation_token", lambda installation_id: {"token": "t"})
    monkeypatch.setattr(github, "list_installation_repositories", lambda token: items)


def item(repo_id, name, **overrides):
    payload = {
        "id": repo_id,
        "full_name": f"{PREFIX}/{name}",
        "html_url": f"https://github.com/{PREFIX}/{name}",
        "private": True,
        "language": "Python",
        "default_branch": "main",
    }
    payload.update(overrides)
    return payload


def stored(name_suffix):
    with main.get_driver().session() as session:
        record = session.run(
            "MATCH (r:Repository {owner: $owner, name: $name}) RETURN r { .* } AS r",
            owner=TEST_USER_ID,
            name=f"{PREFIX}/{name_suffix}",
        ).single()
    return record["r"] if record else None


def test_refresh_on_selected_installation_starts_selected(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    granted(monkeypatch, [item(1, "api")])

    response = client.post("/github/repositories/refresh")

    assert response.status_code == 200
    assert response.json() == {"installations": 1, "repositories": 1, "revoked": 0}
    repo = stored("api")
    assert repo["selected"] is True
    assert repo["github_repo_id"] == 1
    assert repo["full_name"] == f"{PREFIX}/api"
    assert repo["private"] is True
    assert repo["branch"] == "main"
    assert repo["language"] == "Python"
    assert repo["source"] == "github"
    assert repo["access_revoked"] is False


def test_refresh_on_all_installation_starts_unselected(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api")])

    client.post("/github/repositories/refresh")

    assert stored("api")["selected"] is False


def test_refresh_keeps_user_choices(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api")])
    client.post("/github/repositories/refresh")
    client.patch(f"/repositories/{quote(PREFIX + '/api', safe='')}", json={"selected": True, "branch": "dev"})

    client.post("/github/repositories/refresh")

    repo = stored("api")
    assert repo["selected"] is True
    assert repo["branch"] == "dev"


def test_slash_names_work_on_repository_routes(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    granted(monkeypatch, [item(1, "api")])
    client.post("/github/repositories/refresh")
    encoded = quote(f"{PREFIX}/api", safe="")

    assets = client.put(f"/repositories/{encoded}/assets", json={"assets": []})

    assert assets.status_code == 200
    assert assets.json()["repository"] == f"{PREFIX}/api"


def test_rename_updates_existing_repository(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    granted(monkeypatch, [item(1, "old-name")])
    client.post("/github/repositories/refresh")
    granted(monkeypatch, [item(1, "new-name")])

    client.post("/github/repositories/refresh")

    assert stored("old-name") is None
    assert stored("new-name")["github_repo_id"] == 1
    with main.get_driver().session() as session:
        count = session.run(
            "MATCH (r:Repository {owner: $owner, github_repo_id: 1}) RETURN count(r) AS n",
            owner=TEST_USER_ID,
        ).single()["n"]
    assert count == 1


def test_repository_removed_from_grant_is_revoked(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    granted(monkeypatch, [item(1, "keep"), item(2, "drop")])
    client.post("/github/repositories/refresh")
    granted(monkeypatch, [item(1, "keep")])

    response = client.post("/github/repositories/refresh")

    assert response.json()["revoked"] == 1
    assert stored("keep")["access_revoked"] is False
    dropped = stored("drop")
    assert dropped["access_revoked"] is True
    assert dropped["selected"] is False


def test_regranted_repository_is_restored(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    granted(monkeypatch, [item(1, "api")])
    client.post("/github/repositories/refresh")
    granted(monkeypatch, [])
    client.post("/github/repositories/refresh")
    granted(monkeypatch, [item(1, "api")])

    client.post("/github/repositories/refresh")

    assert stored("api")["access_revoked"] is False


def test_refresh_does_not_touch_other_users(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    with main.get_driver().session() as session:
        session.run(
            "CREATE (:Repository {owner: 'someone-else', name: $name, github_repo_id: 1, selected: true})",
            name=f"{PREFIX}/api",
        ).consume()
    granted(monkeypatch, [item(1, "api")])

    client.post("/github/repositories/refresh")

    with main.get_driver().session() as session:
        record = session.run(
            "MATCH (r:Repository {owner: 'someone-else', name: $name}) RETURN r { .* } AS r",
            name=f"{PREFIX}/api",
        ).single()
    assert record["r"].get("full_name") is None
    assert record["r"].get("access_revoked") is None
    assert stored("api")["full_name"] == f"{PREFIX}/api"


def test_refresh_skips_suspended_installations(client, monkeypatch, installation):
    create, created = installation
    create("selected")
    with main.get_driver().session() as session:
        session.run(
            "MATCH (i:GitHubInstallation {id: $id}) SET i.status = 'suspended'", id=created["id"]
        ).consume()
    granted(monkeypatch, [item(1, "api")])

    response = client.post("/github/repositories/refresh")

    assert response.json() == {"installations": 0, "repositories": 0, "revoked": 0}
    assert stored("api") is None


def test_refresh_github_failure_is_502(client, monkeypatch, installation):
    create, _ = installation
    create("selected")

    def broken(token):
        raise github.GitHubError(502, "GitHub is unreachable")

    monkeypatch.setattr(github, "installation_token", lambda installation_id: {"token": "t"})
    monkeypatch.setattr(github, "list_installation_repositories", broken)

    assert client.post("/github/repositories/refresh").status_code == 502


def test_list_installations_counts_granted_and_revoked(client, monkeypatch, installation):
    create, created = installation
    create("selected")
    granted(monkeypatch, [item(1, "keep"), item(2, "drop")])
    client.post("/github/repositories/refresh")
    granted(monkeypatch, [item(1, "keep")])
    client.post("/github/repositories/refresh")

    response = client.get("/github/installations")

    assert response.status_code == 200
    row = next(r for r in response.json() if r["installation"]["id"] == created["id"])
    assert row["repositories"] == 2
    assert row["revoked"] == 1
    assert row["installation"]["repository_selection"] == "selected"


def test_list_installations_hides_other_users(client, installation):
    create, created = installation
    with main.get_driver().session() as session:
        session.run(
            "CREATE (:GitHubInstallation {id: $id, owner: 'someone-else'})", id=created["id"]
        ).consume()

    response = client.get("/github/installations")

    assert all(r["installation"]["id"] != created["id"] for r in response.json())


def test_list_installations_requires_login(client):
    response = client.get("/github/installations", headers={"Authorization": ""})

    assert response.status_code == 401


def test_refresh_requires_login(client):
    response = client.post("/github/repositories/refresh", headers={"Authorization": ""})

    assert response.status_code == 401


def test_list_installation_repositories_follows_pages(monkeypatch):
    pages = {1: 100, 2: 100, 3: 30}
    seen = []

    def fake(method, path, token, body=None):
        page = int(path.rsplit("page=", 1)[1])
        seen.append(page)
        return {"repositories": [{"id": page * 1000 + n} for n in range(pages[page])]}

    monkeypatch.setattr(github, "github_request", fake)

    result = github.list_installation_repositories("t")

    assert len(result) == 230
    assert seen == [1, 2, 3]


def test_list_installation_repositories_is_capped(monkeypatch):
    def fake(method, path, token, body=None):
        page = int(path.rsplit("page=", 1)[1])
        return {"repositories": [{"id": page * 1000 + n} for n in range(100)]}

    monkeypatch.setattr(github, "github_request", fake)

    assert len(github.list_installation_repositories("t")) == github.MAX_REPOSITORIES
