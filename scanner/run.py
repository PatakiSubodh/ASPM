import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import httpx
import yaml

API_URL = os.getenv("ASPM_API_URL", "http://api:8000").rstrip("/")
API_KEY = os.getenv("ASPM_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
CATALOG_PATH = Path(os.getenv("CATALOG_PATH", "/app/catalog.yaml"))
WORK_DIR = Path(os.getenv("WORK_DIR", "/work"))
SCAN_INTERVAL_MINUTES = float(os.getenv("SCAN_INTERVAL_MINUTES", "360"))
SCAN_ON_START = os.getenv("SCAN_ON_START", "true").strip().lower() == "true"
CLONE_TIMEOUT = 600
SCAN_TIMEOUT = 1800
UPLOAD_TIMEOUT = 300

SCANNERS = {
    "trivy": {
        "label": "Trivy",
        "command": lambda path: [
            "trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", str(path),
        ],
    },
}


class ScanError(Exception):
    def __init__(self, error: str, detail: Optional[str] = None):
        super().__init__(error)
        self.error = error
        self.detail = detail


def redact(text: str) -> str:
    return text.replace(GITHUB_TOKEN, "***") if GITHUB_TOKEN else text


def last_line(text: str) -> Optional[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return redact(lines[-1])[:500] if lines else None


def run(command: list[str], error: str, timeout: int) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except subprocess.TimeoutExpired:
        raise ScanError(f"{error} (timed out)")
    except OSError as e:
        raise ScanError(error, last_line(str(e)))
    if result.returncode != 0:
        raise ScanError(error, last_line(result.stderr or result.stdout))
    return result.stdout


def clone_url(url: str) -> str:
    if GITHUB_TOKEN and url.startswith("https://github.com/"):
        return url.replace("https://", f"https://x-access-token:{GITHUB_TOKEN}@", 1)
    return url


def checkout(repo: dict, path: Path) -> str:
    command = ["git", "clone", "--quiet", "--depth", "1"]
    if repo.get("branch"):
        command += ["--branch", str(repo["branch"])]
    command += [clone_url(repo["url"]), str(path)]
    run(command, "Couldn't clone the repository", CLONE_TIMEOUT)
    return run(["git", "-C", str(path), "rev-parse", "HEAD"], "Couldn't read the commit", 60).strip()


def upload(client: httpx.Client, repo: dict, scanner: str, commit: str, report: str) -> None:
    params = {"repo_name": repo["name"], "repo_url": repo["url"], "commit": commit}
    if repo.get("language"):
        params["repo_language"] = repo["language"]
    try:
        res = client.post(
            f"/ingest/{scanner}",
            params=params,
            content=report,
            headers={"Content-Type": "application/json"},
            timeout=UPLOAD_TIMEOUT,
        )
    except httpx.HTTPError as e:
        raise ScanError("Couldn't upload the report", last_line(str(e)))
    if res.is_error:
        raise ScanError(f"Report was rejected ({res.status_code})", last_line(res.text))


def record_failure(
    client: httpx.Client, repo: dict, scanner: str, commit: Optional[str], failure: ScanError
) -> None:
    try:
        client.post(
            "/scans/failed",
            json={
                "repo_name": repo["name"],
                "repo_url": repo["url"],
                "scanner": scanner,
                "commit": commit,
                "error": failure.error[:200],
                "detail": failure.detail,
            },
        )
    except httpx.HTTPError:
        pass


def scan_repository(client: httpx.Client, repo: dict) -> None:
    path = WORK_DIR / re.sub(r"[^a-z0-9._-]", "-", str(repo["name"]).lower())
    shutil.rmtree(path, ignore_errors=True)
    try:
        try:
            commit = checkout(repo, path)
        except ScanError as failure:
            for scanner in SCANNERS:
                record_failure(client, repo, scanner, None, failure)
            return
        for scanner, spec in SCANNERS.items():
            try:
                report = run(spec["command"](path), f"{spec['label']} scan failed", SCAN_TIMEOUT)
                upload(client, repo, scanner, commit, report)
            except ScanError as failure:
                record_failure(client, repo, scanner, commit, failure)
    finally:
        shutil.rmtree(path, ignore_errors=True)


def load_repositories() -> list[dict]:
    data = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {}
    return [r for r in data.get("repositories") or [] if r.get("name") and r.get("url")]


def scan_all() -> None:
    try:
        repositories = load_repositories()
    except (OSError, yaml.YAMLError):
        return
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    with httpx.Client(base_url=API_URL, headers={"X-API-Key": API_KEY}, timeout=30) as client:
        for repo in repositories:
            try:
                scan_repository(client, repo)
            except Exception as e:
                failure = ScanError("Scan crashed", last_line(str(e)))
                for scanner in SCANNERS:
                    record_failure(client, repo, scanner, None, failure)


def main() -> None:
    if not API_KEY:
        raise SystemExit("ASPM_API_KEY is not set")
    interval = SCAN_INTERVAL_MINUTES * 60
    if not SCAN_ON_START:
        time.sleep(interval)
    while True:
        scan_all()
        time.sleep(interval)


if __name__ == "__main__":
    main()
