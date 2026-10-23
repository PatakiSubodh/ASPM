import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import jwt
import pytest

import github
import main
from conftest import TEST_USER_ID

SECRET = "pytest-install-state-secret-0123456789"
REDIRECT = "http://localhost:3000/github/authorized"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("INSTALL_STATE_SECRET", SECRET)
    monkeypatch.setenv("GITHUB_APP_SLUG", "aspm-test")
    monkeypatch.setenv("GITHUB_APP_CLIENT_ID", "Iv1.pytest")
    monkeypatch.setenv("GITHUB_APP_CLIENT_SECRET", "pytest-client-secret")
    monkeypatch.setenv("GITHUB_AUTH_REDIRECT_URI", REDIRECT)
    monkeypatch.setattr(github, "installation_token", lambda installation_id: {"token": "t"})
    monkeypatch.setattr(github, "list_installation_repositories", lambda token: [])


@pytest.fixture
def installation_id(client):
    value = int(uuid4().int % 10**9) + 10**9
    yield value
    with main.get_driver().session() as session:
        session.run("MATCH (i:GitHubInstallation {id: $id}) DETACH DELETE i", id=value).consume()


def fake_github(monkeypatch, installations, token="ghu_user"):
    monkeypatch.setattr(github, "exchange_code", lambda code: token)
    monkeypatch.setattr(github, "list_user_installations", lambda user_token: installations)


def details(installation_id, **overrides):
    payload = {
        "id": installation_id,
        "account": {"login": "octo", "type": "User"},
        "repository_selection": "selected",
        "suspended_at": None,
    }
    payload.update(overrides)
    return payload


def issue(client):
    body = client.post("/github/authorize-url").json()
    state = parse_qs(urlparse(body["url"]).query)["state"][0]
    return state, body["nonce"]


def link(client, state, nonce, code="the-code"):
    return client.post("/github/link", json={"code": code, "state": state, "nonce": nonce})


def test_authorize_url_carries_signed_state(client):
    response = client.post("/github/authorize-url")

    assert response.status_code == 200
    body = response.json()
    parsed = urlparse(body["url"])
    query = parse_qs(parsed.query)
    assert parsed.netloc == "github.com"
    assert parsed.path == "/login/oauth/authorize"
    assert query["client_id"] == ["Iv1.pytest"]
    assert query["redirect_uri"] == [REDIRECT]
    claims = jwt.decode(query["state"][0], SECRET, algorithms=["HS256"])
    assert claims["sub"] == TEST_USER_ID
    assert claims["nonce"] == body["nonce"]
    assert claims["exp"] - claims["iat"] == 600


def test_authorize_url_requires_login(client):
    response = client.post("/github/authorize-url", headers={"Authorization": ""})

    assert response.status_code == 401


@pytest.mark.parametrize(
    "missing",
    ["INSTALL_STATE_SECRET", "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET", "GITHUB_AUTH_REDIRECT_URI"],
)
def test_authorize_url_without_config_is_503(client, monkeypatch, missing):
    monkeypatch.delenv(missing)

    assert client.post("/github/authorize-url").status_code == 503


def test_link_links_only_installations_github_returns(client, monkeypatch, installation_id):
    fake_github(monkeypatch, [details(installation_id)])
    state, nonce = issue(client)

    response = link(client, state, nonce)

    assert response.status_code == 200
    body = response.json()
    assert body["conflicts"] == 0
    assert body["install_url"] is None
    [item] = body["linked"]
    installation = item["installation"]
    assert installation["id"] == installation_id
    assert installation["owner"] == TEST_USER_ID
    assert installation["account_login"] == "octo"
    assert installation["account_type"] == "User"
    assert installation["repository_selection"] == "selected"
    assert installation["status"] == "active"
    assert item["sync"] == {"repositories": 0, "revoked": 0}


def test_link_ignores_installation_ids_sent_by_the_client(client, monkeypatch, installation_id):
    fake_github(monkeypatch, [])
    state, nonce = issue(client)

    response = client.post(
        "/github/link",
        json={"code": "c", "state": state, "nonce": nonce, "installation_id": installation_id},
    )

    assert response.status_code == 200
    assert response.json()["linked"] == []
    with main.get_driver().session() as session:
        count = session.run(
            "MATCH (i:GitHubInstallation {id: $id}) RETURN count(i) AS n", id=installation_id
        ).single()["n"]
    assert count == 0


def test_link_with_no_installations_returns_install_page(client, monkeypatch):
    fake_github(monkeypatch, [])
    state, nonce = issue(client)

    body = link(client, state, nonce).json()

    assert body["linked"] == []
    assert body["conflicts"] == 0
    assert body["install_url"] == "https://github.com/apps/aspm-test/installations/new"


def test_link_is_idempotent_for_same_user(client, monkeypatch, installation_id):
    fake_github(monkeypatch, [details(installation_id)])

    for _ in range(2):
        state, nonce = issue(client)
        assert link(client, state, nonce).status_code == 200

    with main.get_driver().session() as session:
        count = session.run(
            "MATCH (:User {id: $user})-[r:HAS_INSTALLATION]->(:GitHubInstallation {id: $id}) "
            "RETURN count(r) AS n",
            user=TEST_USER_ID,
            id=installation_id,
        ).single()["n"]
    assert count == 1


def test_suspended_installation_is_recorded_without_sync(client, monkeypatch, installation_id):
    fake_github(monkeypatch, [details(installation_id, suspended_at="2026-10-21T00:00:00Z")])
    state, nonce = issue(client)

    [item] = link(client, state, nonce).json()["linked"]

    assert item["installation"]["status"] == "suspended"
    assert item["sync"] is None


def test_installation_linked_to_another_user_is_a_conflict(client, monkeypatch, installation_id):
    fake_github(monkeypatch, [details(installation_id)])
    with main.get_driver().session() as session:
        session.run(
            "CREATE (:GitHubInstallation {id: $id, owner: 'someone-else'})", id=installation_id
        ).consume()
    state, nonce = issue(client)

    body = link(client, state, nonce).json()

    assert body["linked"] == []
    assert body["conflicts"] == 1
    assert body["install_url"] is None
    with main.get_driver().session() as session:
        owner = session.run(
            "MATCH (i:GitHubInstallation {id: $id}) RETURN i.owner AS owner", id=installation_id
        ).single()["owner"]
    assert owner == "someone-else"


def test_tampered_state_is_rejected(client, monkeypatch):
    fake_github(monkeypatch, [])
    state, nonce = issue(client)

    assert link(client, state[:-2] + "xx", nonce).status_code == 400


def test_state_signed_with_another_secret_is_rejected(client, monkeypatch):
    fake_github(monkeypatch, [])
    now = int(time.time())
    forged = jwt.encode(
        {"sub": TEST_USER_ID, "nonce": "n", "iat": now, "exp": now + 600},
        "some-other-secret-0123456789abcdef",
        algorithm="HS256",
    )

    assert link(client, forged, "n").status_code == 400


def test_expired_state_is_rejected(client, monkeypatch):
    fake_github(monkeypatch, [])
    issued = github.create_state(TEST_USER_ID, now=int(time.time()) - 3600)

    assert link(client, issued["state"], issued["nonce"]).status_code == 400


def test_state_for_another_user_is_rejected(client, monkeypatch):
    fake_github(monkeypatch, [])
    issued = github.create_state("someone-else")

    assert link(client, issued["state"], issued["nonce"]).status_code == 400


def test_wrong_nonce_is_rejected(client, monkeypatch):
    fake_github(monkeypatch, [])
    state, _ = issue(client)

    assert link(client, state, "not-the-nonce").status_code == 400


def test_rejected_state_never_reaches_github(client, monkeypatch):
    calls = []
    monkeypatch.setattr(github, "exchange_code", lambda code: calls.append(code) or "t")
    monkeypatch.setattr(github, "list_user_installations", lambda token: calls.append(token) or [])
    state, _ = issue(client)

    link(client, state, "not-the-nonce")

    assert calls == []


def test_rejected_code_is_400(client, monkeypatch):
    def rejected(code):
        raise github.GitHubError(400, "GitHub rejected the authorization code")

    monkeypatch.setattr(github, "exchange_code", rejected)
    state, nonce = issue(client)

    assert link(client, state, nonce).status_code == 400


def test_user_token_is_used_to_list_installations(client, monkeypatch):
    seen = {}
    monkeypatch.setattr(github, "exchange_code", lambda code: seen.setdefault("code", code) and "ghu_x")
    monkeypatch.setattr(
        github, "list_user_installations", lambda token: seen.setdefault("token", token) and []
    )
    state, nonce = issue(client)

    link(client, state, nonce, code="abc")

    assert seen == {"code": "abc", "token": "ghu_x"}


def test_github_failure_is_502(client, monkeypatch):
    def broken(code):
        raise github.GitHubError(502, "GitHub is unreachable")

    monkeypatch.setattr(github, "exchange_code", broken)
    state, nonce = issue(client)

    assert link(client, state, nonce).status_code == 502


def test_link_requires_login(client):
    response = client.post(
        "/github/link",
        json={"code": "c", "state": "s", "nonce": "n"},
        headers={"Authorization": ""},
    )

    assert response.status_code == 401
