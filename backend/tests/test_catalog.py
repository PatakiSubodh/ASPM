from test_ingest_lifecycle import finding_id, report


def catalog(repo: str, *assets: str) -> dict:
    return {
        "repositories": [
            {
                "name": repo,
                "url": f"https://git.example.com/{repo}",
                "language": "Python",
                "branch": "main",
                "assets": [
                    {
                        "name": f"{repo}-{a}",
                        "environment": "production",
                        "type": "Docker container",
                        "internet_facing": a == "web",
                    }
                    for a in assets
                ],
            }
        ]
    }


def post_catalog(client, body: dict) -> dict:
    res = client.post("/catalog", json=body)
    assert res.status_code == 200, res.text
    return res.json()


def scan(client, repo: str, body: dict, **params) -> dict:
    res = client.post("/ingest/trivy", params={"repo_name": repo, **params}, json=body)
    assert res.status_code == 201, res.text
    return res.json()


def affected(client, repo: str, package: str) -> list[str]:
    res = client.get(f"/findings/{finding_id(repo, package)}")
    assert res.status_code == 200, res.text
    return sorted(a["name"] for a in res.json()["assets"])


def catalog_entry(client, repo: str) -> dict:
    res = client.get("/catalog")
    assert res.status_code == 200, res.text
    return next(e for e in res.json() if e["repository"]["name"] == repo)


def test_catalog_links_repo_to_assets(client, repo):
    result = post_catalog(client, catalog(repo, "api", "web"))

    assert (result["repositories"], result["assets"], result["linked"]) == (1, 2, 2)
    entry = catalog_entry(client, repo)
    assert entry["repository"]["branch"] == "main"
    assert [a["name"] for a in entry["assets"]] == [f"{repo}-api", f"{repo}-web"]
    assert all(a["source"] == "catalog" for a in entry["assets"])
    assert entry["open_total"] == 0


def test_catalog_is_idempotent(client, repo):
    post_catalog(client, catalog(repo, "api"))
    result = post_catalog(client, catalog(repo, "api"))

    assert (result["linked"], result["unlinked"], result["backfilled"]) == (0, 0, 0)


def test_scan_without_asset_params_derives_affects(client, repo):
    post_catalog(client, catalog(repo, "api", "web"))
    scan(client, repo, report("pyyaml"))

    assert affected(client, repo, "pyyaml") == [f"{repo}-api", f"{repo}-web"]
    assert catalog_entry(client, repo)["open_total"] == 1


def test_catalog_change_backfills_and_prunes(client, repo):
    post_catalog(client, catalog(repo, "api"))
    scan(client, repo, report("pyyaml", "jinja2"))

    result = post_catalog(client, catalog(repo, "web"))

    assert (result["linked"], result["unlinked"], result["backfilled"]) == (1, 1, 2)
    assert affected(client, repo, "pyyaml") == [f"{repo}-web"]
    assert affected(client, repo, "jinja2") == [f"{repo}-web"]


def test_unmapping_keeps_explicit_affects(client, repo):
    post_catalog(client, catalog(repo, "web"))
    scan(
        client,
        repo,
        report("pyyaml"),
        asset_name=f"{repo}-api",
        asset_environment="staging",
        asset_type="Docker container",
    )

    post_catalog(client, catalog(repo))

    assert affected(client, repo, "pyyaml") == [f"{repo}-api"]
    assert catalog_entry(client, repo)["assets"] == []


def test_unmapped_repo_findings_have_no_asset(client, repo):
    scan(client, repo, report("requests"), repo_url=f"https://git.example.com/{repo}")

    res = client.get("/findings")
    assert res.status_code == 200, res.text
    rows = [f for f in res.json() if f["repository"]["name"] == repo]
    assert len(rows) == 1
    assert rows[0]["asset"] is None


def test_unknown_repo_without_url_is_rejected(client, repo):
    res = client.post("/ingest/trivy", params={"repo_name": repo}, json=report("pyyaml"))

    assert res.status_code == 422
    assert client.get(f"/findings/{finding_id(repo, 'pyyaml')}").status_code == 404


def test_partial_asset_params_are_rejected(client, repo):
    post_catalog(client, catalog(repo, "api"))
    res = client.post(
        "/ingest/trivy",
        params={"repo_name": repo, "asset_name": f"{repo}-api"},
        json=report("pyyaml"),
    )

    assert res.status_code == 422


def test_duplicate_catalog_repositories_are_rejected(client, repo):
    body = catalog(repo, "api")
    body["repositories"] *= 2

    assert client.post("/catalog", json=body).status_code == 422
