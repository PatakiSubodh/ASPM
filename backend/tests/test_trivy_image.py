from test_catalog import catalog
from test_ingest_lifecycle import PACKAGES, report

IMAGE = "registry.example.com/app:1.0"


def image_report(*packages: str, name: str = IMAGE) -> dict:
    body = report(*packages)
    body["ArtifactName"] = name
    body["Results"][0]["Target"] = "debian 12 (debian)"
    body["Results"][0]["Class"] = "os-pkgs"
    return body


def setup(client, repo, image=IMAGE):
    body = catalog(repo, "api", "web")
    body["repositories"][0]["assets"][0]["image"] = image
    assert client.post("/catalog", json=body).status_code == 200


def post(client, repo, body, asset="api", **params):
    return client.post(
        "/ingest/trivy",
        params={"repo_name": repo, "mode": "image", "asset_name": f"{repo}-{asset}", **params},
        json=body,
    )


def affected(client, finding_id):
    res = client.get(f"/findings/{finding_id}")
    assert res.status_code == 200, res.text
    return sorted(a["name"] for a in res.json()["assets"]), res.json()["vulnerability"]


def test_image_findings_attach_only_to_matching_asset(client, repo):
    setup(client, repo)
    res = post(client, repo, image_report("jinja2"))
    assert res.status_code == 201, res.text
    ids = res.json()["ids"]
    assert ids == [f"{repo}:{repo}-api:image:jinja2:{PACKAGES['jinja2'][0]}".upper()]
    assets, vulnerability = affected(client, ids[0])
    assert assets == [f"{repo}-api"]
    assert vulnerability["type"] == "container"
    assert vulnerability["scanner"] == "trivy-image"
    assert vulnerability["location"] == "debian 12 (debian)"


def test_image_scan_does_not_resolve_fs_findings(client, repo):
    setup(client, repo)
    fs = client.post(
        "/ingest/trivy", params={"repo_name": repo}, json=report("pyyaml")
    ).json()["ids"][0]
    post(client, repo, image_report("jinja2"))
    post(client, repo, image_report("requests"))
    _, vulnerability = affected(client, fs)
    assert vulnerability["status"] == "open"


def test_image_scan_resolves_only_its_own_asset(client, repo):
    setup(client, repo)
    first = post(client, repo, image_report("jinja2")).json()["ids"][0]
    second = post(client, repo, image_report("requests"))
    assert second.json()["resolved"] == 1
    assert affected(client, first)[1]["status"] == "resolved"


def test_image_mode_rejects_mismatched_or_unmapped(client, repo):
    setup(client, repo)
    assert post(client, repo, image_report("jinja2", name="other:2.0")).status_code == 422
    assert post(client, repo, image_report("jinja2"), asset="web").status_code == 422
    res = client.post(
        "/ingest/trivy", params={"repo_name": repo, "mode": "image"}, json=image_report("jinja2")
    )
    assert res.status_code == 422
