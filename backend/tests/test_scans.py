from test_ingest_lifecycle import ingest, report, vuln


def fail(client, repo: str, **body) -> dict:
    res = client.post(
        "/scans/failed",
        json={"repo_name": repo, "scanner": "trivy", "error": "Trivy scan failed", **body},
    )
    assert res.status_code == 201, res.text
    return res.json()


def scans(client, repo: str) -> list[dict]:
    res = client.get("/scans", params={"repo": repo})
    assert res.status_code == 200, res.text
    return res.json()


def test_successful_scan_is_marked_succeeded(client, repo):
    ingest(client, repo, report("pyyaml"))

    assert scans(client, repo)[0]["status"] == "succeeded"


def test_failed_scan_is_recorded_without_touching_findings(client, repo):
    ingest(client, repo, report("pyyaml", "jinja2"))
    before = vuln(client, repo, "pyyaml")
    last_scanned = client.get("/catalog").json()
    last_scanned = next(e for e in last_scanned if e["repository"]["name"] == repo)

    result = fail(client, repo, commit="abc123", detail="exit status 1")

    assert result["status"] == "failed"
    latest = scans(client, repo)[0]
    assert latest["id"] == result["scan_id"]
    assert (latest["status"], latest["error"], latest["detail"], latest["commit"]) == (
        "failed",
        "Trivy scan failed",
        "exit status 1",
        "abc123",
    )
    assert (latest["ingested"], latest["resolved"], latest["reopened"]) == (0, 0, 0)
    after = vuln(client, repo, "pyyaml")
    assert after["status"] == "open"
    assert after["last_scan_id"] == before["last_scan_id"]
    catalog = next(e for e in client.get("/catalog").json() if e["repository"]["name"] == repo)
    assert catalog["repository"]["last_scanned_at"] == last_scanned["repository"]["last_scanned_at"]


def test_failed_scan_for_new_repo_needs_url(client, repo):
    res = client.post(
        "/scans/failed",
        json={"repo_name": repo, "scanner": "trivy", "error": "Couldn't clone the repository"},
    )
    assert res.status_code == 422

    fail(client, repo, repo_url=f"https://git.example.com/{repo}", error="Couldn't clone the repository")
    assert scans(client, repo)[0]["status"] == "failed"


def test_failed_scan_rejects_bad_input(client, repo):
    body = {"repo_name": repo, "repo_url": "https://git.example.com/x", "error": "x"}

    assert client.post("/scans/failed", json={**body, "scanner": "Trivy!"}).status_code == 422
    assert client.post("/scans/failed", json={**body, "scanner": "trivy", "error": ""}).status_code == 422


def failing(client, repo: str) -> list[dict]:
    res = client.get("/scans/failing")
    assert res.status_code == 200, res.text
    return [f for f in res.json() if f["repository"] == repo]


def test_failing_lists_repo_whose_latest_scan_failed(client, repo):
    ingest(client, repo, report("pyyaml"))
    succeeded_at = scans(client, repo)[0]["finished_at"]
    result = fail(client, repo)

    rows = failing(client, repo)

    assert len(rows) == 1
    assert rows[0]["scanner"] == "trivy"
    assert rows[0]["error"] == "Trivy scan failed"
    assert rows[0]["failed_at"] == scans(client, repo)[0]["started_at"]
    assert rows[0]["last_succeeded_at"] == succeeded_at
    assert result["status"] == "failed"


def test_failing_clears_after_successful_rescan(client, repo):
    ingest(client, repo, report("pyyaml"))
    fail(client, repo)
    ingest(client, repo, report("pyyaml"))

    assert failing(client, repo) == []


def test_failing_is_per_scanner(client, repo):
    ingest(client, repo, report("pyyaml"))
    fail(client, repo, scanner="semgrep", error="Semgrep scan failed")
    ingest(client, repo, report("pyyaml"))

    rows = failing(client, repo)

    assert [r["scanner"] for r in rows] == ["semgrep"]


def test_never_scanned_successfully(client, repo):
    fail(client, repo, repo_url=f"https://git.example.com/{repo}", error="Couldn't clone the repository")

    rows = failing(client, repo)

    assert len(rows) == 1
    assert rows[0]["last_succeeded_at"] is None
