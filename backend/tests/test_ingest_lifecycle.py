import pytest

PACKAGES = {
    "jinja2": ("CVE-2024-22195", "MEDIUM"),
    "pyyaml": ("CVE-2020-14343", "CRITICAL"),
    "requests": ("CVE-2023-32681", "HIGH"),
}


def report(*packages: str) -> dict:
    return {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": PACKAGES[p][0],
                        "PkgName": p,
                        "InstalledVersion": "1.0",
                        "FixedVersion": "2.0",
                        "Severity": PACKAGES[p][1],
                        "Title": f"{p} issue",
                    }
                    for p in packages
                ],
            }
        ]
    }


def finding_id(repo: str, package: str) -> str:
    return f"{repo}:{package}:{PACKAGES[package][0]}".upper()


def ingest(client, repo: str, body: dict, **params) -> dict:
    query = {
        "repo_name": repo,
        "repo_url": f"https://git.example.com/{repo}",
        "asset_name": f"{repo}-api",
        "asset_environment": "production",
        "asset_type": "Docker container",
        "asset_internet_facing": "true",
        **params,
    }
    res = client.post("/ingest/trivy", params=query, json=body)
    assert res.status_code == 201, res.text
    return res.json()


def vuln(client, repo: str, package: str) -> dict:
    res = client.get(f"/findings/{finding_id(repo, package)}")
    assert res.status_code == 200, res.text
    return res.json()["vulnerability"]


def set_status(client, repo: str, package: str, status: str) -> None:
    res = client.patch(f"/findings/{finding_id(repo, package)}", json={"status": status})
    assert res.status_code == 200, res.text


def test_first_scan_creates_open_findings(client, repo):
    result = ingest(client, repo, report("jinja2", "pyyaml", "requests"), commit="abc123")

    assert result["ingested"] == 3
    assert (result["resolved"], result["reopened"], result["skipped"]) == (0, 0, 0)
    v = vuln(client, repo, "pyyaml")
    assert v["status"] == "open"
    assert v["scanner"] == "trivy"
    assert v["type"] == "sca"
    assert v["package"] == "pyyaml"
    assert v["fixed_version"] == "2.0"
    assert v["location"] == "requirements.txt"
    assert v["first_seen"] == v["last_seen"]
    assert v["last_scan_id"] == result["scan_id"]


def test_rescan_is_idempotent_and_keeps_first_seen(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml"))
    before = vuln(client, repo, "jinja2")

    result = ingest(client, repo, report("jinja2", "pyyaml"))

    assert (result["ingested"], result["resolved"], result["reopened"]) == (2, 0, 0)
    after = vuln(client, repo, "jinja2")
    assert after["first_seen"] == before["first_seen"]
    assert after["last_seen"] > before["last_seen"]


def test_missing_findings_are_auto_resolved(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml", "requests"))

    result = ingest(client, repo, report("jinja2"))

    assert result["resolved"] == 2
    assert vuln(client, repo, "jinja2")["status"] == "open"
    resolved = vuln(client, repo, "pyyaml")
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"]


def test_resolved_finding_that_returns_is_reopened(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml"))
    ingest(client, repo, report("jinja2"))

    result = ingest(client, repo, report("jinja2", "pyyaml"))

    assert result["reopened"] == 1
    v = vuln(client, repo, "pyyaml")
    assert v["status"] == "open"
    assert v["reopened_at"]
    assert "resolved_at" not in v


def test_human_statuses_survive_rescans(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml", "requests"))
    set_status(client, repo, "jinja2", "in_progress")
    set_status(client, repo, "pyyaml", "accepted_risk")
    set_status(client, repo, "requests", "false_positive")

    ingest(client, repo, report("jinja2", "pyyaml", "requests"))

    assert vuln(client, repo, "jinja2")["status"] == "in_progress"
    assert vuln(client, repo, "pyyaml")["status"] == "accepted_risk"
    assert vuln(client, repo, "requests")["status"] == "false_positive"


def test_auto_resolve_skips_accepted_and_false_positive(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml", "requests"))
    set_status(client, repo, "jinja2", "in_progress")
    set_status(client, repo, "pyyaml", "accepted_risk")
    set_status(client, repo, "requests", "false_positive")

    result = ingest(client, repo, report())

    assert result["resolved"] == 1
    assert vuln(client, repo, "jinja2")["status"] == "resolved"
    assert vuln(client, repo, "pyyaml")["status"] == "accepted_risk"
    assert vuln(client, repo, "requests")["status"] == "false_positive"


def test_partial_scan_never_resolves(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml"))

    result = ingest(client, repo, report("jinja2"), partial="true")

    assert result["resolved"] == 0
    assert vuln(client, repo, "pyyaml")["status"] == "open"


def test_auto_resolve_is_scoped_to_scanner(client, repo):
    res = client.post(
        "/findings",
        json={
            "repository": {"name": repo, "url": f"https://git.example.com/{repo}"},
            "vulnerability": {"id": f"{repo}:manual-1", "severity": "LOW", "description": "manual"},
            "asset": {"name": f"{repo}-api", "environment": "production", "type": "Docker container"},
        },
    )
    assert res.status_code == 201, res.text

    ingest(client, repo, report())

    manual = client.get(f"/findings/{repo}:manual-1").json()["vulnerability"]
    assert manual["status"] == "open"
    assert manual["scanner"] == "manual"


def test_unknown_severity_is_skipped_and_duplicates_merged(client, repo):
    body = report("jinja2", "jinja2")
    body["Results"][0]["Vulnerabilities"].append(
        {"VulnerabilityID": "CVE-2000-0001", "PkgName": "legacy", "Severity": "UNKNOWN"}
    )

    result = ingest(client, repo, body)

    assert result["ingested"] == 1
    assert result["skipped"] == 1


def test_status_filters(client, repo):
    ingest(client, repo, report("jinja2", "pyyaml"))
    ingest(client, repo, report("jinja2"))

    def ids(status=None):
        params = {"status": status} if status else {}
        return {
            f["vulnerability"]["id"]
            for f in client.get("/findings", params=params).json()
            if f["repository"]["name"] == repo
        }

    assert ids() == {finding_id(repo, "jinja2")}
    assert ids("resolved") == {finding_id(repo, "pyyaml")}
    assert ids("all") == {finding_id(repo, "jinja2"), finding_id(repo, "pyyaml")}
    assert client.get("/findings", params={"status": "bogus"}).status_code == 422

    graph = client.get("/graph").json()
    node_ids = {n["id"] for n in graph["nodes"]}
    assert f"Vulnerability:{finding_id(repo, 'jinja2')}" in node_ids
    assert f"Vulnerability:{finding_id(repo, 'pyyaml')}" not in node_ids


def test_scans_are_recorded_newest_first(client, repo):
    first = ingest(client, repo, report("jinja2", "pyyaml"), commit="abc123")
    second = ingest(client, repo, report("jinja2"), commit="def456")

    scans = client.get("/scans", params={"repo": repo.upper()}).json()

    assert [s["id"] for s in scans] == [second["scan_id"], first["scan_id"]]
    latest = scans[0]
    assert latest["repository"] == repo
    assert latest["scanner"] == "trivy"
    assert latest["commit"] == "def456"
    assert (latest["ingested"], latest["resolved"], latest["reopened"]) == (1, 1, 0)
    assert latest["finished_at"] >= latest["started_at"]


@pytest.mark.parametrize(
    ("finding", "body", "expected"),
    [
        ("NOPE:NOPE:NOPE", {"status": "open"}, 404),
        (None, {"status": "done"}, 422),
    ],
)
def test_patch_rejects_bad_input(client, repo, finding, body, expected):
    ingest(client, repo, report("jinja2"))
    target = finding or finding_id(repo, "jinja2")

    assert client.patch(f"/findings/{target}", json=body).status_code == expected


def test_api_key_required(client):
    assert client.get("/findings", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/health", headers={"X-API-Key": ""}).status_code == 200
