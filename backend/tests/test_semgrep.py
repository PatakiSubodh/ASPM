from connectors import semgrep


def result(check_id="python.sql", path="app/db.py", line=10, severity="ERROR", lines="query(x)", **extra):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "extra": {"message": "bad", "severity": severity, "lines": lines, **extra},
    }


def parse(*results):
    return semgrep.parse(semgrep.SemgrepReport.model_validate({"results": list(results)}), "demo")


def ingest(client, repo, body, **params):
    res = client.post(
        "/ingest/semgrep",
        params={"repo_name": repo, "repo_url": f"https://git.example.com/{repo}", **params},
        json=body,
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_severity_mapping_and_skip():
    findings, skipped = parse(
        result(check_id="a", severity="ERROR"),
        result(check_id="b", severity="WARNING"),
        result(check_id="c", severity="INFO"),
        result(check_id="d", severity="CRITICAL"),
        result(check_id="e", severity="WEIRD"),
    )
    assert [f.severity for f in findings] == ["HIGH", "MEDIUM", "LOW", "CRITICAL"]
    assert skipped == 1


def test_id_ignores_line_number():
    first, _ = parse(result(line=10))
    moved, _ = parse(result(line=42))
    assert first[0].id == moved[0].id
    assert first[0].location == "app/db.py:10"
    assert moved[0].location == "app/db.py:42"


def test_id_falls_back_when_lines_require_login():
    findings, _ = parse(result(lines="requires login", line=3), result(lines="requires login", line=9))
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2


def test_cwe_string_or_list():
    single, _ = parse(result(metadata={"cwe": "CWE-89"}))
    many, _ = parse(result(metadata={"cwe": ["CWE-89", "CWE-20"]}))
    assert single[0].cwe == ["CWE-89"]
    assert many[0].cwe == ["CWE-89", "CWE-20"]


def test_ingest_resolves_when_finding_disappears(client, repo):
    body = {"results": [result(), result(check_id="python.xss", lines="render(y)")]}
    first = ingest(client, repo, body)
    assert len(first["ids"]) == 2
    second = ingest(client, repo, {"results": [result(line=77)]})
    assert second["resolved"] == 1
    assert second["ids"][0] in first["ids"]
    res = client.get(f"/findings/{second['ids'][0]}")
    vulnerability = res.json()["vulnerability"]
    assert vulnerability["scanner"] == "semgrep"
    assert vulnerability["type"] == "sast"
    assert vulnerability["location"] == "app/db.py:77"
