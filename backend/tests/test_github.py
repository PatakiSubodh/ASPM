import io
import json
import urllib.error

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import github

APP_ID = "123456"
NOW = 1_800_000_000


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def configured(monkeypatch, pem):
    monkeypatch.setenv("GITHUB_APP_ID", APP_ID)
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", pem.replace("\n", "\\n"))
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def decode(token, key):
    return jwt.decode(
        token,
        key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_iat": False},
    )


def test_app_jwt_claims(configured, key):
    claims = decode(github.app_jwt(now=NOW), key)

    assert claims == {"iss": APP_ID, "iat": NOW - 60, "exp": NOW + 540}
    assert claims["exp"] - NOW <= 9 * 60


def test_app_jwt_reads_key_from_path(monkeypatch, key, pem, tmp_path):
    path = tmp_path / "app.pem"
    path.write_text(pem, encoding="utf-8")
    monkeypatch.setenv("GITHUB_APP_ID", APP_ID)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", str(path))

    assert decode(github.app_jwt(now=NOW), key)["iss"] == APP_ID


def test_app_jwt_requires_config(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)
    with pytest.raises(RuntimeError):
        github.app_jwt()

    monkeypatch.setenv("GITHUB_APP_ID", APP_ID)
    with pytest.raises(RuntimeError):
        github.app_jwt()


def test_installation_token_request(configured, key, monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["auth"] = request.get_header("Authorization")
        seen["body"] = json.loads(request.data) if request.data else None
        return FakeResponse(json.dumps({"token": "ghs_secret", "expires_at": "2026-10-19T12:00:00Z"}).encode())

    monkeypatch.setattr(github.urllib.request, "urlopen", fake_urlopen)

    result = github.installation_token(42)

    assert result == {"token": "ghs_secret", "expires_at": "2026-10-19T12:00:00Z"}
    assert seen["url"] == "https://api.github.com/app/installations/42/access_tokens"
    assert seen["method"] == "POST"
    assert seen["body"] is None
    assert decode(seen["auth"].removeprefix("Bearer "), key)["iss"] == APP_ID


def test_installation_token_can_be_scoped_to_repositories(configured, monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout):
        seen["body"] = json.loads(request.data)
        return FakeResponse(json.dumps({"token": "t", "expires_at": "e"}).encode())

    monkeypatch.setattr(github.urllib.request, "urlopen", fake_urlopen)

    github.installation_token(42, repository_ids=[7])

    assert seen["body"] == {"repository_ids": [7], "permissions": {"contents": "read"}}


def test_github_errors_do_not_leak_the_token(configured, monkeypatch):
    def failing_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 404, "ghs_secret not found", {}, io.BytesIO(b"ghs_secret")
        )

    monkeypatch.setattr(github.urllib.request, "urlopen", failing_urlopen)

    with pytest.raises(github.GitHubError) as error:
        github.installation_token(42)

    assert error.value.status == 404
    assert "ghs_secret" not in error.value.message


def test_unreachable_github_maps_to_502(configured, monkeypatch):
    def failing_urlopen(request, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(github.urllib.request, "urlopen", failing_urlopen)

    with pytest.raises(github.GitHubError) as error:
        github.installation_token(42)

    assert error.value.status == 502
