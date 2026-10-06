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
