import github
import main
from conftest import TEST_USER_ID
from test_github_sync import PREFIX, granted, installation, item, stored  # noqa: F401


def test_available_lists_only_unlisted_repositories(client, monkeypatch, installation):
    create, _ = installation
    create("selected")
    granted(monkeypatch, [item(1, "api"), item(2, "web")])
    client.post("/github/repositories/refresh")
    with main.get_driver().session() as session:
        session.run(
            "MATCH (r:Repository {owner: $owner, name: $name}) DETACH DELETE r",
            owner=TEST_USER_ID,
            name=f"{PREFIX}/web",
        ).consume()

    response = client.get("/github/available-repositories")

    assert response.status_code == 200
    available = response.json()["repositories"]
    assert [r["full_name"] for r in available] == [f"{PREFIX}/web"]
    assert available[0]["branch"] == "main"
    assert available[0]["private"] is True


def test_available_is_empty_without_installation(client):
    response = client.get("/github/available-repositories")

    assert response.status_code == 200
    assert response.json() == {"repositories": []}


def test_add_github_repository_links_and_selects(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api"), item(2, "web")])

    response = client.post("/github/repositories", json={"full_name": f"{PREFIX}/API"})

    assert response.status_code == 201
    assert response.json() == {"name": f"{PREFIX}/api"}
    api = stored("api")
    assert api["selected"] is True
    assert api["source"] == "github"
    assert api["access_revoked"] is False
    assert stored("web")["selected"] is False


def test_add_github_repository_rejects_ungranted_and_malformed(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api")])

    missing = client.post("/github/repositories", json={"full_name": f"{PREFIX}/nope"})
    malformed = client.post("/github/repositories", json={"full_name": "../etc/passwd"})

    assert missing.status_code == 404
    assert malformed.status_code == 422


def test_branches_come_from_github_for_granted_repository(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api")])
    monkeypatch.setattr(github, "list_branches", lambda token, full_name: ["main", "dev"])

    response = client.get("/github/branches", params={"repo": f"{PREFIX}/api"})

    assert response.status_code == 200
    assert response.json() == {"branches": ["main", "dev"], "default": "main"}


def test_branches_reject_ungranted_and_malformed(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api")])

    assert client.get("/github/branches", params={"repo": f"{PREFIX}/nope"}).status_code == 404
    assert client.get("/github/branches", params={"repo": "a/b/c"}).status_code == 422


def test_revoked_repository_cannot_be_added_or_branched(client, monkeypatch, installation):
    create, _ = installation
    create("all")
    granted(monkeypatch, [item(1, "api"), item(2, "drop")])
    client.post("/github/repositories/refresh")
    granted(monkeypatch, [item(1, "api")])
    client.post("/github/repositories/refresh")
    monkeypatch.setattr(github, "list_branches", lambda token, full_name: ["main"])

    added = client.post("/github/repositories", json={"full_name": f"{PREFIX}/drop"})
    branches = client.get("/github/branches", params={"repo": f"{PREFIX}/drop"})
    available = client.get("/github/available-repositories").json()["repositories"]

    assert added.status_code == 404
    assert branches.status_code == 404
    assert available == []
    assert stored("drop")["access_revoked"] is True
    assert stored("drop")["selected"] is False


def test_paused_installation_grants_nothing(client, monkeypatch, installation):
    create, created = installation
    create("all")
    with main.get_driver().session() as session:
        session.run(
            "MATCH (i:GitHubInstallation {id: $id}) SET i.status = 'disconnected'",
            id=created["id"],
        ).consume()

    def fail(*args, **kwargs):
        raise AssertionError("GitHub must not be called")

    monkeypatch.setattr(github, "installation_token", fail)

    assert client.get("/github/available-repositories").json() == {"repositories": []}
    assert client.get("/github/branches", params={"repo": f"{PREFIX}/api"}).status_code == 404
    assert client.post("/github/repositories", json={"full_name": f"{PREFIX}/api"}).status_code == 404


def test_list_branches_pages_and_caps(monkeypatch):
    pages = []

    def fake(method, path, token, body=None):
        number = int(path.rsplit("page=", 1)[1])
        pages.append(number)
        if number == 1:
            return [{"name": f"b{i}"} for i in range(100)]
        return [{"name": "last"}]

    monkeypatch.setattr(github, "github_request", fake)

    branches = github.list_branches("t", "org/repo")

    assert pages == [1, 2]
    assert len(branches) == 101
    assert branches[-1] == "last"
