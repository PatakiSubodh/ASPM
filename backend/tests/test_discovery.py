from test_catalog import affected, catalog, catalog_entry, post_catalog, scan
from test_ingest_lifecycle import report


def discovered(name: str, source: str | None = None, **labels: str) -> dict:
    all_labels = {"aspm.environment": "production", **labels}
    if source:
        all_labels["org.opencontainers.image.source"] = source
    return {"name": name, "image": f"{name}:latest", "labels": all_labels}


def discover(client, *assets: dict) -> dict:
    res = client.post("/assets/discover", json={"source": "docker", "assets": list(assets)})
    assert res.status_code == 200, res.text
    return res.json()


def test_discovery_links_asset_to_repo_by_url(client, repo):
    post_catalog(client, catalog(repo))
    scan(client, repo, report("pyyaml"))

    result = discover(
        client,
        discovered(
            f"{repo}-api", f"https://GIT.example.com/{repo}.git/", **{"aspm.internet_facing": "true"}
        ),
    )

    assert (result["assets"], result["linked"], result["backfilled"]) == (1, 1, 1)
    assert result["unmatched"] == []
    assert affected(client, repo, "pyyaml") == [f"{repo}-api"]
    asset = catalog_entry(client, repo)["assets"][0]
    assert (asset["source"], asset["environment"], asset["internet_facing"]) == (
        "docker",
        "production",
        True,
    )
    assert asset["type"] == "Docker container"
    assert asset["last_discovered_at"]


def test_discovery_is_idempotent(client, repo):
    post_catalog(client, catalog(repo))
    body = discovered(f"{repo}-api", f"https://git.example.com/{repo}")
    discover(client, body)
    result = discover(client, body)

    assert (result["linked"], result["backfilled"]) == (0, 0)


def test_discovery_keeps_unmatched_assets_unlinked(client, repo):
    post_catalog(client, catalog(repo))
    result = discover(
        client,
        discovered(f"{repo}-api", "https://git.example.com/unknown"),
        discovered(f"{repo}-web"),
    )

    assert result["linked"] == 0
    assert result["unmatched"] == [f"{repo}-api", f"{repo}-web"]
    assert catalog_entry(client, repo)["assets"] == []


def test_discovery_requires_environment_label(client, repo):
    res = client.post(
        "/assets/discover",
        json={"assets": [{"name": f"{repo}-api", "labels": {"aspm.internet_facing": "true"}}]},
    )

    assert res.status_code == 422


def test_discovery_rejects_invalid_internet_facing(client, repo):
    res = client.post(
        "/assets/discover",
        json={"assets": [discovered(f"{repo}-api", **{"aspm.internet_facing": "yes"})]},
    )

    assert res.status_code == 422
