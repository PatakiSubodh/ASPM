import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import jwt
import pytest

import github
import main
from conftest import TEST_USER_ID

SECRET = "pytest-install-state-secret-0123456789"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("INSTALL_STATE_SECRET", SECRET)
    monkeypatch.setenv("GITHUB_APP_SLUG", "aspm-test")
    monkeypatch.setattr(github, "installation_token", lambda installation_id: {"token": "t"})
    monkeypatch.setattr(github, "list_installation_repositories", lambda token: [])


@pytest.fixture
def installation_id(client):
    value = int(uuid4().int % 10**9) + 10**9
    yield value
    with main.get_driver().session() as session:
        session.run("MATCH (i:GitHubInstallation {id: $id}) DETACH DELETE i", id=value).consume()


def fake_installation(monkeypatch, **overrides):
    payload = {
        "id": 1,
        "account": {"login": "octo", "type": "User"},
        "repository_selection": "selected",
        "suspended_at": None,
    }
    payload.update(overrides)
    monkeypatch.setattr(github, "get_installation", lambda installation_id: payload)


def issue(client):
    body = client.post("/github/install-url").json()
    state = parse_qs(urlparse(body["url"]).query)["state"][0]
    return state, body["nonce"]


def link(client, installation_id, state, nonce):
    return client.post(
        "/github/installations",
        json={"installation_id": installation_id, "state": state, "nonce": nonce},
    )


def test_install_url_carries_signed_state(client):
    response = client.post("/github/install-url")

    assert response.status_code == 200
    body = response.json()
    parsed = urlparse(body["url"])
    assert parsed.netloc == "github.com"
    assert parsed.path == "/apps/aspm-test/installations/new"
    claims = jwt.decode(parse_qs(parsed.query)["state"][0], SECRET, algorithms=["HS256"])
    assert claims["sub"] == TEST_USER_ID
    assert claims["nonce"] == body["nonce"]
    assert claims["exp"] - claims["iat"] == 600


def test_install_url_requires_login(client):
    response = client.post("/github/install-url", headers={"Authorization": ""})

    assert response.status_code == 401


def test_install_url_without_config_is_503(client, monkeypatch):
    monkeypatch.delenv("INSTALL_STATE_SECRET")

    assert client.post("/github/install-url").status_code == 503


def test_link_installation(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    state, nonce = issue(client)

    response = link(client, installation_id, state, nonce)

    assert response.status_code == 201
    installation = response.json()["installation"]
    assert installation["id"] == installation_id
    assert installation["owner"] == TEST_USER_ID
    assert installation["account_login"] == "octo"
    assert installation["account_type"] == "User"
    assert installation["repository_selection"] == "selected"
    assert installation["status"] == "active"


def test_link_installation_is_idempotent_for_same_user(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    state, nonce = issue(client)

    assert link(client, installation_id, state, nonce).status_code == 201
    assert link(client, installation_id, state, nonce).status_code == 201

    with main.get_driver().session() as session:
        count = session.run(
            "MATCH (:User {id: $user})-[r:HAS_INSTALLATION]->(:GitHubInstallation {id: $id}) "
            "RETURN count(r) AS n",
            user=TEST_USER_ID,
            id=installation_id,
        ).single()["n"]
    assert count == 1


def test_suspended_installation_is_recorded(client, monkeypatch, installation_id):
    fake_installation(monkeypatch, suspended_at="2026-10-21T00:00:00Z")
    state, nonce = issue(client)

    response = link(client, installation_id, state, nonce)

    assert response.json()["installation"]["status"] == "suspended"


def test_tampered_state_is_rejected(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    state, nonce = issue(client)

    assert link(client, installation_id, state[:-2] + "xx", nonce).status_code == 400


def test_state_signed_with_another_secret_is_rejected(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    now = int(time.time())
    forged = jwt.encode(
        {"sub": TEST_USER_ID, "nonce": "n", "iat": now, "exp": now + 600},
        "some-other-secret-0123456789abcdef",
        algorithm="HS256",
    )

    assert link(client, installation_id, forged, "n").status_code == 400


def test_expired_state_is_rejected(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    issued = github.create_state(TEST_USER_ID, now=int(time.time()) - 3600)

    assert link(client, installation_id, issued["state"], issued["nonce"]).status_code == 400


def test_state_for_another_user_is_rejected(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    issued = github.create_state("someone-else")

    assert link(client, installation_id, issued["state"], issued["nonce"]).status_code == 400


def test_wrong_nonce_is_rejected(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    state, _ = issue(client)

    assert link(client, installation_id, state, "not-the-nonce").status_code == 400


def test_installation_linked_to_another_user_is_409(client, monkeypatch, installation_id):
    fake_installation(monkeypatch)
    with main.get_driver().session() as session:
        session.run(
            "CREATE (:GitHubInstallation {id: $id, owner: 'someone-else'})", id=installation_id
        ).consume()
    state, nonce = issue(client)

    assert link(client, installation_id, state, nonce).status_code == 409
    with main.get_driver().session() as session:
        owner = session.run(
            "MATCH (i:GitHubInstallation {id: $id}) RETURN i.owner AS owner", id=installation_id
        ).single()["owner"]
    assert owner == "someone-else"


def test_unknown_installation_is_404(client, monkeypatch, installation_id):
    def missing(installation_id):
        raise github.GitHubError(404, "GitHub responded with 404")

    monkeypatch.setattr(github, "get_installation", missing)
    state, nonce = issue(client)

    assert link(client, installation_id, state, nonce).status_code == 404


def test_github_failure_is_502(client, monkeypatch, installation_id):
    def broken(installation_id):
        raise github.GitHubError(502, "GitHub is unreachable")

    monkeypatch.setattr(github, "get_installation", broken)
    state, nonce = issue(client)

    assert link(client, installation_id, state, nonce).status_code == 502


def test_link_installation_requires_login(client):
    response = client.post(
        "/github/installations",
        json={"installation_id": 1, "state": "s", "nonce": "n"},
        headers={"Authorization": ""},
    )

    assert response.status_code == 401
