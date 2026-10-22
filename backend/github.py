import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

import jwt

GITHUB_API_VERSION = "2022-11-28"
REQUEST_TIMEOUT = 15
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 540
STATE_LIFETIME_SECONDS = 600
STATE_ALGORITHM = "HS256"
REPOSITORIES_PER_PAGE = 100
MAX_REPOSITORIES = 500


class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class InvalidState(Exception):
    pass


def _api_url() -> str:
    return os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")


def _private_key() -> str:
    inline = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    if inline.strip():
        return inline.replace("\\n", "\n")
    path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
    if not path:
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH is not set")
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def app_jwt(now: Optional[int] = None) -> str:
    app_id = os.getenv("GITHUB_APP_ID", "").strip()
    if not app_id:
        raise RuntimeError("GITHUB_APP_ID is not set")
    issued = int(time.time() if now is None else now)
    claims = {
        "iss": app_id,
        "iat": issued - JWT_BACKDATE_SECONDS,
        "exp": issued + JWT_LIFETIME_SECONDS,
    }
    return jwt.encode(claims, _private_key(), algorithm="RS256")


def github_request(method: str, path: str, token: str, body: Optional[dict] = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "aspm-api",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{_api_url()}{path}", data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raise GitHubError(error.code, f"GitHub responded with {error.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise GitHubError(502, "GitHub is unreachable") from None


def installation_token(
    installation_id: int, repository_ids: Optional[list[int]] = None
) -> dict:
    body = None
    if repository_ids:
        body = {"repository_ids": repository_ids, "permissions": {"contents": "read"}}
    payload = github_request(
        "POST", f"/app/installations/{int(installation_id)}/access_tokens", app_jwt(), body
    )
    return {"token": payload["token"], "expires_at": payload["expires_at"]}


def _state_secret() -> str:
    secret = os.getenv("INSTALL_STATE_SECRET", "").strip()
    if not secret:
        raise RuntimeError("INSTALL_STATE_SECRET is not set")
    return secret


def create_state(user_id: str, now: Optional[int] = None) -> dict:
    issued = int(time.time() if now is None else now)
    nonce = secrets.token_urlsafe(16)
    claims = {
        "sub": user_id,
        "nonce": nonce,
        "iat": issued,
        "exp": issued + STATE_LIFETIME_SECONDS,
    }
    state = jwt.encode(claims, _state_secret(), algorithm=STATE_ALGORITHM)
    return {"state": state, "nonce": nonce}


def verify_state(state: str, user_id: str, nonce: str) -> None:
    try:
        claims = jwt.decode(
            state,
            _state_secret(),
            algorithms=[STATE_ALGORITHM],
            options={"require": ["exp", "sub", "nonce"]},
        )
    except jwt.PyJWTError:
        raise InvalidState() from None
    if not secrets.compare_digest(str(claims["sub"]).encode(), user_id.encode()):
        raise InvalidState()
    if not secrets.compare_digest(str(claims["nonce"]).encode(), nonce.encode()):
        raise InvalidState()


def install_url(state: str) -> str:
    slug = os.getenv("GITHUB_APP_SLUG", "").strip()
    if not slug:
        raise RuntimeError("GITHUB_APP_SLUG is not set")
    query = urllib.parse.urlencode({"state": state})
    return f"https://github.com/apps/{urllib.parse.quote(slug)}/installations/new?{query}"


def get_installation(installation_id: int) -> dict:
    return github_request("GET", f"/app/installations/{int(installation_id)}", app_jwt())


def list_installation_repositories(token: str) -> list[dict]:
    repositories: list[dict] = []
    page = 1
    while len(repositories) < MAX_REPOSITORIES:
        payload = github_request(
            "GET",
            f"/installation/repositories?per_page={REPOSITORIES_PER_PAGE}&page={page}",
            token,
        )
        batch = payload.get("repositories", [])
        repositories.extend(batch)
        if len(batch) < REPOSITORIES_PER_PAGE:
            break
        page += 1
    return repositories[:MAX_REPOSITORIES]
