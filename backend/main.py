"""
ASPM Backend — FastAPI service backed by Neo4j.

Graph model:
    (:Repository)-[:CONTAINS]->(:Vulnerability)-[:AFFECTS]->(:Asset)

This lets us answer the core ASPM question: "which production assets are
exposed by which vulnerable code, and where did that vulnerability come from?"
"""

import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional
from uuid import uuid4

import yaml
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from neo4j import Driver
from neo4j.exceptions import ConstraintError

import github
from auth import get_current_user, init_auth
from connectors import semgrep, trivy
from db import close_driver, connect_driver, get_driver, migrate_ownership
from ingest import _now, ingest_batch, require_known_repository, run_scan
from models import (
    ACTIVE_STATUSES,
    STATUSES,
    AssetIn,
    AssetUpdate,
    CatalogIn,
    DiscoveryIn,
    FindingIngest,
    GitHubLinkIn,
    GitHubRepositoryIn,
    IngestParams,
    TrivyIngestParams,
    RepositoryAssetsIn,
    RepositoryCreate,
    RepositoryIn,
    RepositoryUpdate,
    ScanFailureIn,
    ScanRunIn,
    StatusUpdate,
    _normalize_key,
)
from risk import SEVERITIES, asset_risk

load_dotenv()

ASPM_API_KEY = os.getenv("ASPM_API_KEY", "")
CATALOG_PATH = os.getenv("CATALOG_PATH", "/app/catalog.yaml")
DEV_OWNER = os.getenv("ASPM_DEV_OWNER", "")
SCAN_COOLDOWN_DAYS = int(os.getenv("SCAN_COOLDOWN_DAYS", "7"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ASPM_API_KEY:
        raise RuntimeError("ASPM_API_KEY is not set")
    init_auth()
    db = connect_driver()
    if DEV_OWNER:
        migrate_ownership(db, DEV_OWNER)
        load_catalog_file(db, DEV_OWNER)
    yield
    close_driver()


app = FastAPI(title="ASPM Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: Optional[str] = Security(api_key_header)) -> None:
    if not api_key or not secrets.compare_digest(api_key, ASPM_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def machine_owner(owner: Optional[str] = Query(None)) -> str:
    resolved = (owner or DEV_OWNER).strip()
    if not resolved:
        raise HTTPException(status_code=422, detail="owner is required")
    return resolved


protected = [Depends(require_api_key)]
signed_in = [Depends(get_current_user)]
Owner = Annotated[str, Depends(machine_owner)]
CurrentUser = Annotated[dict, Depends(get_current_user)]


def _parse_statuses(status: str) -> Optional[list[str]]:
    if status.strip().lower() == "all":
        return None
    statuses = [s.strip().lower() for s in status.split(",") if s.strip()]
    invalid = [s for s in statuses if s not in STATUSES]
    if invalid or not statuses:
        raise HTTPException(status_code=422, detail=f"Invalid status filter: {status}")
    return statuses


def _parse_filter(
    value: Optional[str], name: str, allowed: Optional[tuple] = None, upper: bool = False
) -> Optional[list[str]]:
    items = [i.strip() for i in (value or "").split(",") if i.strip()]
    items = [i.upper() if upper else i.lower() for i in items]
    invalid = [i for i in items if allowed is not None and i not in allowed]
    if invalid:
        raise HTTPException(status_code=422, detail=f"Invalid {name} filter: {value}")
    return items or None


def _query_findings(
    owner: str,
    status: str,
    q: Optional[str],
    severity: Optional[str],
    priority: Optional[str],
    environment: Optional[str],
    internet_facing: Optional[bool],
    scanner: Optional[str],
    repo: Optional[str],
) -> list[dict]:
    query = """
    MATCH (repo:Repository {owner: $owner})-[:CONTAINS]->(vuln:Vulnerability)
    WHERE $statuses IS NULL OR vuln.status IN $statuses
    OPTIONAL MATCH (vuln)-[:AFFECTS]->(asset:Asset)
    WITH repo, vuln, asset
    WHERE ($q IS NULL OR any(
        value IN [vuln.id, vuln.cve, vuln.package, repo.name, asset.name]
        WHERE value IS NOT NULL AND toLower(value) CONTAINS $q
    ))
      AND ($severities IS NULL OR vuln.severity IN $severities)
      AND ($scanners IS NULL OR toLower(vuln.scanner) IN $scanners)
      AND ($repos IS NULL OR toLower(repo.name) IN $repos)
      AND ($environments IS NULL OR toLower(asset.environment) IN $environments)
      AND ($internet_facing IS NULL OR coalesce(asset.internet_facing, false) = $internet_facing)
    RETURN repo { .* } AS repository, vuln { .* } AS vulnerability, asset { .* } AS asset
    """
    needle = (q or "").strip().lower() or None
    with get_driver().session() as session:
        findings = [
            {
                "repository": record["repository"],
                "vulnerability": record["vulnerability"],
                "asset": record["asset"],
                "risk": asset_risk(record["vulnerability"]["severity"], record["asset"] or {}),
            }
            for record in session.run(
                query,
                owner=owner,
                statuses=_parse_statuses(status),
                q=needle,
                severities=_parse_filter(severity, "severity", SEVERITIES, upper=True),
                scanners=_parse_filter(scanner, "scanner"),
                repos=_parse_filter(repo, "repo"),
                environments=_parse_filter(environment, "environment"),
                internet_facing=internet_facing,
            )
        ]
    priorities = _parse_filter(priority, "priority", ("P1", "P2", "P3", "P4"), upper=True)
    if priorities:
        findings = [f for f in findings if f["risk"]["priority"] in priorities]
    return findings


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


CATALOG_UPSERT_QUERY = """
UNWIND $repositories AS r
MERGE (repo:Repository {owner: $owner, name: r.name})
SET repo.url = r.url,
    repo.language = coalesce(r.language, repo.language),
    repo.branch = coalesce(r.branch, repo.branch)
WITH repo, r
UNWIND r.assets AS a
MERGE (asset:Asset {owner: $owner, name: a.name})
SET asset.environment = a.environment,
    asset.type = a.type,
    asset.internet_facing = a.internet_facing,
    asset.image = a.image,
    asset.source = 'catalog'
MERGE (repo)-[deploys:DEPLOYS_TO]->(asset)
  ON CREATE SET deploys.source = 'catalog'
"""

CATALOG_PRUNE_QUERY = """
UNWIND $repositories AS r
MATCH (repo:Repository {owner: $owner, name: r.name})-[deploys:DEPLOYS_TO {source: 'catalog'}]->(asset:Asset)
WHERE NOT asset.name IN [a IN r.assets | a.name]
CALL (repo, asset) {
  MATCH (repo)-[:CONTAINS]->(:Vulnerability)-[derived:AFFECTS {source: 'catalog'}]->(asset)
  DELETE derived
}
DELETE deploys
RETURN count(deploys) AS unlinked
"""

CATALOG_BACKFILL_QUERY = """
UNWIND $repositories AS r
MATCH (repo:Repository {owner: $owner, name: r.name})-[:DEPLOYS_TO]->(asset:Asset)
MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
MERGE (vuln)-[affects:AFFECTS]->(asset)
  ON CREATE SET affects.source = 'catalog'
"""


def apply_catalog(tx, owner: str, catalog: CatalogIn) -> dict:
    repositories = [r.model_dump() for r in catalog.repositories]
    linked = tx.run(CATALOG_UPSERT_QUERY, owner=owner, repositories=repositories).consume().counters
    unlinked = tx.run(CATALOG_PRUNE_QUERY, owner=owner, repositories=repositories).single()["unlinked"]
    backfilled = tx.run(CATALOG_BACKFILL_QUERY, owner=owner, repositories=repositories).consume().counters
    return {
        "repositories": len(repositories),
        "assets": len({a["name"] for r in repositories for a in r["assets"]}),
        "linked": linked.relationships_created,
        "unlinked": unlinked,
        "backfilled": backfilled.relationships_created,
    }


def load_catalog_file(db: Driver, owner: str) -> None:
    path = Path(CATALOG_PATH)
    if not path.is_file():
        return
    catalog = CatalogIn.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    with db.session() as session:
        session.execute_write(apply_catalog, owner, catalog)


@app.post("/catalog", dependencies=protected)
def upsert_catalog(catalog: CatalogIn, owner: Owner):
    with get_driver().session() as session:
        return session.execute_write(apply_catalog, owner, catalog)


@app.get("/catalog", dependencies=signed_in)
def get_catalog(current_user: CurrentUser):
    query = """
    MATCH (repo:Repository {owner: $owner})
    OPTIONAL MATCH (repo)-[:DEPLOYS_TO]->(asset:Asset)
    WITH repo, collect(asset { .* }) AS assets
    OPTIONAL MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
    WHERE vuln.status IN $statuses
    RETURN repo { .* } AS repository, assets, count(vuln) AS open_total
    ORDER BY repository.name
    """
    with get_driver().session() as session:
        return [
            {
                "repository": record["repository"],
                "assets": sorted(record["assets"], key=lambda a: a["name"]),
                "open_total": record["open_total"],
            }
            for record in session.run(query, owner=current_user["id"], statuses=ACTIVE_STATUSES)
        ]


DISCOVERY_UPSERT_QUERY = """
UNWIND $assets AS a
MERGE (asset:Asset {owner: $owner, name: a.name})
SET asset.environment = a.environment,
    asset.type = 'Docker container',
    asset.internet_facing = a.internet_facing,
    asset.image = coalesce(asset.image, a.image),
    asset.source = $source,
    asset.last_discovered_at = $now,
    asset.status = 'active',
    asset.decommissioned_at = null
WITH asset, a
CALL (asset, a) {
  MATCH (repo:Repository {owner: $owner, name: a.repository})
  MERGE (repo)-[deploys:DEPLOYS_TO]->(asset)
    ON CREATE SET deploys.source = $source
}
"""

DISCOVERY_BACKFILL_QUERY = """
UNWIND $assets AS a
MATCH (repo:Repository {owner: $owner, name: a.repository})-[:DEPLOYS_TO]->(asset:Asset {owner: $owner, name: a.name})
MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
MERGE (vuln)-[affects:AFFECTS]->(asset)
  ON CREATE SET affects.source = 'catalog'
"""

DISCOVERY_DECOMMISSION_QUERY = """
MATCH (asset:Asset {owner: $owner, source: $source})
WHERE NOT asset.name IN $names AND coalesce(asset.status, 'active') <> 'decommissioned'
SET asset.status = 'decommissioned',
    asset.decommissioned_at = $now
RETURN collect(asset.name) AS names
"""


def _normalize_url(url: str) -> str:
    return url.strip().lower().rstrip("/").removesuffix(".git")


def apply_discovery(tx, owner: str, discovery: DiscoveryIn, now: str) -> dict:
    repos = {
        _normalize_url(record["url"]): record["name"]
        for record in tx.run(
            "MATCH (r:Repository {owner: $owner}) WHERE r.url IS NOT NULL RETURN r.name AS name, r.url AS url",
            owner=owner,
        )
    }
    assets = []
    for a in discovery.assets:
        source_url = a.labels.get("org.opencontainers.image.source")
        assets.append(
            {
                "name": a.name,
                "image": a.image,
                "environment": a.labels["aspm.environment"].strip(),
                "internet_facing": a.labels.get("aspm.internet_facing", "false").strip().lower()
                == "true",
                "repository": repos.get(_normalize_url(source_url)) if source_url else None,
            }
        )
    linked = tx.run(
        DISCOVERY_UPSERT_QUERY, owner=owner, assets=assets, source=discovery.source, now=now
    ).consume().counters
    backfilled = tx.run(DISCOVERY_BACKFILL_QUERY, owner=owner, assets=assets).consume().counters
    decommissioned = tx.run(
        DISCOVERY_DECOMMISSION_QUERY,
        owner=owner,
        source=discovery.source,
        names=[a["name"] for a in assets],
        now=now,
    ).single()["names"]
    return {
        "assets": len(assets),
        "linked": linked.relationships_created,
        "unmatched": sorted(a["name"] for a in assets if a["repository"] is None),
        "backfilled": backfilled.relationships_created,
        "decommissioned": sorted(decommissioned),
    }


@app.post("/assets/discover", dependencies=protected)
def discover_assets(discovery: DiscoveryIn, owner: Owner):
    with get_driver().session() as session:
        return session.execute_write(apply_discovery, owner, discovery, _now())


@app.post("/findings", status_code=201, dependencies=protected)
def ingest_finding(finding: FindingIngest, owner: Owner):
    vuln = finding.vulnerability
    require_known_repository(owner, finding.repository)
    with get_driver().session() as session:
        session.execute_write(
            ingest_batch,
            owner,
            finding.repository,
            finding.asset,
            "manual",
            None,
            [
                {
                    "id": vuln.id,
                    "cve": vuln.cve,
                    "severity": vuln.severity,
                    "description": vuln.description,
                }
            ],
            _now(),
        )
    return {
        "created": {
            "repository": finding.repository.name,
            "vulnerability": vuln.id,
            "asset": finding.asset.name if finding.asset else None,
        }
    }


@app.patch("/findings/{finding_id}")
def update_finding_status(
    finding_id: str,
    update: StatusUpdate,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    query = """
    MATCH (vuln:Vulnerability {owner: $owner, id: $id})
    WITH vuln, vuln.status = $status AS unchanged
    SET vuln.status = $status,
        vuln.status_changed_at = CASE WHEN unchanged THEN vuln.status_changed_at ELSE $now END,
        vuln.status_changed_by = CASE WHEN unchanged THEN vuln.status_changed_by ELSE $user_email END,
        vuln.status_changed_by_id = CASE WHEN unchanged THEN vuln.status_changed_by_id ELSE $user_id END,
        vuln.resolved_at = CASE
          WHEN $status <> 'resolved' THEN null
          WHEN unchanged THEN vuln.resolved_at
          ELSE $now
        END
    RETURN vuln { .* } AS vulnerability
    """
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(
                query,
                owner=current_user["id"],
                id=" ".join(finding_id.split()).upper(),
                status=update.status,
                now=_now(),
                user_email=current_user["email"],
                user_id=current_user["id"],
            ).single()
        )
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"vulnerability": record["vulnerability"]}


@app.get("/findings", dependencies=signed_in)
def list_findings(
    current_user: CurrentUser,
    status: str = ",".join(ACTIVE_STATUSES),
    q: Optional[str] = Query(None, max_length=200),
    severity: Optional[str] = Query(None, max_length=100),
    priority: Optional[str] = Query(None, max_length=100),
    environment: Optional[str] = Query(None, max_length=200),
    internet_facing: Optional[bool] = None,
    scanner: Optional[str] = Query(None, max_length=200),
    repo: Optional[str] = Query(None, max_length=500),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Return a page of repository -> vulnerability -> asset chains, ranked by risk."""
    findings = _query_findings(
        current_user["id"], status, q, severity, priority, environment, internet_facing, scanner, repo
    )
    findings.sort(
        key=lambda f: (
            -f["risk"]["score"],
            f["vulnerability"]["id"],
            (f["asset"] or {}).get("name", ""),
        )
    )
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding["vulnerability"]["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "items": findings[offset : offset + limit],
        "total": len(findings),
        "counts": counts,
        "limit": limit,
        "offset": offset,
    }


@app.get("/findings/{finding_id}", dependencies=signed_in)
def get_finding(finding_id: str, current_user: CurrentUser):
    query = """
    MATCH (vuln:Vulnerability {owner: $owner, id: $id})
    OPTIONAL MATCH (repo:Repository)-[:CONTAINS]->(vuln)
    WITH vuln, collect(DISTINCT repo { .* }) AS repositories
    OPTIONAL MATCH (vuln)-[:AFFECTS]->(asset:Asset)
    RETURN vuln { .* } AS vulnerability, repositories, collect(DISTINCT asset { .* }) AS assets
    """
    db = get_driver()
    with db.session() as session:
        record = session.run(
            query, owner=current_user["id"], id=" ".join(finding_id.split()).upper()
        ).single()

    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    severity = record["vulnerability"]["severity"]
    asset_risks = {a["name"]: asset_risk(severity, a) for a in record["assets"]}
    return {
        "vulnerability": record["vulnerability"],
        "repositories": record["repositories"],
        "assets": record["assets"],
        "risk": max(asset_risks.values(), key=lambda r: r["score"], default=None),
        "asset_risks": asset_risks,
    }


@app.get("/assets", dependencies=signed_in)
def list_assets(current_user: CurrentUser):
    query = """
    MATCH (asset:Asset {owner: $owner})
    OPTIONAL MATCH (vuln:Vulnerability)-[:AFFECTS]->(asset)
    WHERE vuln.status IN $statuses
    RETURN asset { .* } AS asset, collect(vuln.severity) AS severities
    ORDER BY asset.name
    """
    db = get_driver()
    with db.session() as session:
        return [
            {
                "asset": record["asset"],
                "open_by_severity": {s: record["severities"].count(s) for s in SEVERITIES},
                "open_total": len(record["severities"]),
                "risk": max(
                    (asset_risk(s, record["asset"]) for s in record["severities"]),
                    key=lambda r: r["score"],
                    default=None,
                ),
            }
            for record in session.run(query, owner=current_user["id"], statuses=ACTIVE_STATUSES)
        ]


def _path_key(value: str) -> str:
    try:
        return _normalize_key(value).lower()
    except ValueError:
        raise HTTPException(status_code=422, detail="name must not be blank")


REPOSITORY_PROJECTION = "repo { .*, selected: coalesce(repo.selected, true) }"


@app.get("/repositories")
def list_repositories(current_user: CurrentUser):
    query = f"""
    MATCH (repo:Repository {{owner: $owner}})
    OPTIONAL MATCH (repo)-[:DEPLOYS_TO]->(asset:Asset {{owner: $owner}})
    WITH repo, collect(asset {{ .* }}) AS assets
    OPTIONAL MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
    WHERE vuln.status IN $statuses
    RETURN {REPOSITORY_PROJECTION} AS repository, assets, count(vuln) AS open_total
    ORDER BY repository.name
    """
    with get_driver().session() as session:
        return [
            {
                "repository": record["repository"],
                "assets": sorted(record["assets"], key=lambda a: a["name"]),
                "open_total": record["open_total"],
            }
            for record in session.run(query, owner=current_user["id"], statuses=ACTIVE_STATUSES)
        ]


@app.post("/repositories", status_code=201)
def create_repository(repository: RepositoryCreate, current_user: CurrentUser):
    query = f"""
    CREATE (repo:Repository {{owner: $owner, source: 'manual', selected: true, created_at: $now}})
    SET repo += $fields
    RETURN {REPOSITORY_PROJECTION} AS repository
    """
    try:
        with get_driver().session() as session:
            record = session.execute_write(
                lambda tx: tx.run(
                    query,
                    owner=current_user["id"],
                    fields=repository.model_dump(),
                    now=_now(),
                ).single()
            )
    except ConstraintError:
        raise HTTPException(status_code=409, detail="Repository already exists")
    return {"repository": record["repository"]}


@app.patch("/repositories/{name:path}")
def update_repository(name: str, update: RepositoryUpdate, current_user: CurrentUser):
    query = f"""
    MATCH (repo:Repository {{owner: $owner, name: $name}})
    SET repo += $changes
    RETURN {REPOSITORY_PROJECTION} AS repository
    """
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(
                query,
                owner=current_user["id"],
                name=_path_key(name),
                changes=update.model_dump(exclude_unset=True),
            ).single()
        )
    if record is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    return {"repository": record["repository"]}


REPOSITORY_ASSETS_PRUNE_QUERY = """
MATCH (repo:Repository {owner: $owner, name: $name})-[deploys:DEPLOYS_TO]->(asset:Asset)
WHERE NOT asset.name IN $assets
CALL (repo, asset) {
  MATCH (repo)-[:CONTAINS]->(:Vulnerability)-[derived:AFFECTS {source: 'catalog'}]->(asset)
  DELETE derived
}
DELETE deploys
RETURN count(deploys) AS unlinked
"""

REPOSITORY_ASSETS_LINK_QUERY = """
MATCH (repo:Repository {owner: $owner, name: $name})
UNWIND $assets AS asset_name
MATCH (asset:Asset {owner: $owner, name: asset_name})
MERGE (repo)-[deploys:DEPLOYS_TO]->(asset)
  ON CREATE SET deploys.source = 'manual'
"""

REPOSITORY_ASSETS_BACKFILL_QUERY = """
MATCH (repo:Repository {owner: $owner, name: $name})-[:DEPLOYS_TO]->(asset:Asset)
MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
MERGE (vuln)-[affects:AFFECTS]->(asset)
  ON CREATE SET affects.source = 'catalog'
"""


def apply_repository_assets(tx, owner: str, name: str, assets: list[str]) -> Optional[dict]:
    exists = tx.run(
        "MATCH (repo:Repository {owner: $owner, name: $name}) RETURN count(repo) > 0 AS exists",
        owner=owner,
        name=name,
    ).single()["exists"]
    if not exists:
        return None
    found = {
        record["name"]
        for record in tx.run(
            "MATCH (a:Asset {owner: $owner}) WHERE a.name IN $assets RETURN a.name AS name",
            owner=owner,
            assets=assets,
        )
    }
    missing = sorted(set(assets) - found)
    if missing:
        return {"missing": missing}
    unlinked = tx.run(
        REPOSITORY_ASSETS_PRUNE_QUERY, owner=owner, name=name, assets=assets
    ).single()["unlinked"]
    linked = tx.run(
        REPOSITORY_ASSETS_LINK_QUERY, owner=owner, name=name, assets=assets
    ).consume().counters
    backfilled = tx.run(
        REPOSITORY_ASSETS_BACKFILL_QUERY, owner=owner, name=name
    ).consume().counters
    return {
        "repository": name,
        "assets": assets,
        "linked": linked.relationships_created,
        "unlinked": unlinked,
        "backfilled": backfilled.relationships_created,
    }


@app.put("/repositories/{name:path}/assets")
def set_repository_assets(name: str, body: RepositoryAssetsIn, current_user: CurrentUser):
    with get_driver().session() as session:
        result = session.execute_write(
            apply_repository_assets, current_user["id"], _path_key(name), body.assets
        )
    if result is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    if "missing" in result:
        raise HTTPException(
            status_code=422, detail=f"Unknown assets: {', '.join(result['missing'])}"
        )
    return result


@app.post("/assets", status_code=201)
def create_asset(asset: AssetIn, current_user: CurrentUser):
    query = """
    CREATE (asset:Asset {owner: $owner, source: 'manual'})
    SET asset += $fields
    RETURN asset { .* } AS asset
    """
    try:
        with get_driver().session() as session:
            record = session.execute_write(
                lambda tx: tx.run(
                    query, owner=current_user["id"], fields=asset.model_dump()
                ).single()
            )
    except ConstraintError:
        raise HTTPException(status_code=409, detail="Asset already exists")
    return {"asset": record["asset"]}


@app.patch("/assets/{name}")
def update_asset(name: str, update: AssetUpdate, current_user: CurrentUser):
    query = """
    MATCH (asset:Asset {owner: $owner, name: $name})
    SET asset += $changes
    RETURN asset { .* } AS asset
    """
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(
                query,
                owner=current_user["id"],
                name=_path_key(name),
                changes=update.model_dump(exclude_unset=True),
            ).single()
        )
    if record is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"asset": record["asset"]}


@app.delete("/assets/{name}", status_code=204)
def delete_asset(name: str, current_user: CurrentUser):
    query = "MATCH (asset:Asset {owner: $owner, name: $name}) DETACH DELETE asset"
    with get_driver().session() as session:
        counters = session.execute_write(
            lambda tx: tx.run(query, owner=current_user["id"], name=_path_key(name))
            .consume()
            .counters
        )
    if counters.nodes_deleted == 0:
        raise HTTPException(status_code=404, detail="Asset not found")


LINK_INSTALLATION = """
MATCH (u:User {id: $owner})
MERGE (i:GitHubInstallation {id: $id})
ON CREATE SET i.owner = $owner, i.created_at = $now
WITH u, i
WHERE i.owner = $owner
MERGE (u)-[:HAS_INSTALLATION]->(i)
SET i.account_login = $login,
    i.account_type = $account_type,
    i.repository_selection = $selection,
    i.status = $status,
    i.updated_at = $now
RETURN i { .* } AS installation
"""


@app.post("/github/authorize-url")
def github_authorize_url(current_user: CurrentUser):
    try:
        issued = github.create_state(current_user["id"])
        url = github.authorize_url(issued["state"])
    except RuntimeError:
        raise HTTPException(status_code=503, detail="GitHub App is not configured")
    return {"url": url, "nonce": issued["nonce"]}


def _link_installation(owner: str, details: dict) -> Optional[dict]:
    account = details.get("account") or {}
    try:
        with get_driver().session() as session:
            record = session.execute_write(
                lambda tx: tx.run(
                    LINK_INSTALLATION,
                    owner=owner,
                    id=details["id"],
                    login=account.get("login"),
                    account_type=account.get("type"),
                    selection=details.get("repository_selection"),
                    status="suspended" if details.get("suspended_at") else "active",
                    now=_now(),
                ).single()
            )
    except ConstraintError:
        return None
    return record["installation"] if record else None


@app.post("/github/link")
def link_github_installations(body: GitHubLinkIn, current_user: CurrentUser):
    owner = current_user["id"]
    try:
        github.verify_state(body.state, owner, body.nonce)
        user_token = github.exchange_code(body.code)
        accessible = github.list_user_installations(user_token)
        install_page = github.install_url()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="GitHub App is not configured")
    except github.InvalidState:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization state")
    except github.GitHubError as error:
        if error.status == 400:
            raise HTTPException(status_code=400, detail="GitHub rejected the authorization")
        raise HTTPException(status_code=502, detail=error.message)
    linked = []
    conflicts = 0
    for details in accessible:
        installation = _link_installation(owner, details)
        if installation is None:
            conflicts += 1
            continue
        sync = (
            _sync_installation(owner, details["id"], details.get("repository_selection"))
            if installation["status"] == "active"
            else None
        )
        if installation["status"] == "active" and installation.get("account_login"):
            with get_driver().session() as session:
                session.execute_write(
                    lambda tx: tx.run(
                        FORGET_STALE_INSTALLATIONS,
                        owner=owner,
                        id=details["id"],
                        login=installation["account_login"],
                    ).consume()
                )
        linked.append({"installation": installation, "sync": sync})
    return {
        "linked": linked,
        "conflicts": conflicts,
        "install_url": install_page if not linked and not conflicts else None,
    }


SYNC_RENAME_QUERY = """
UNWIND $repos AS r
MATCH (repo:Repository {owner: $owner, github_repo_id: r.id})
WHERE repo.name <> r.name
SET repo.name = r.name
"""

SYNC_UPSERT_QUERY = """
MATCH (i:GitHubInstallation {id: $id, owner: $owner})
UNWIND $repos AS r
MERGE (repo:Repository {owner: $owner, name: r.name})
  ON CREATE SET repo.selected = $selected, repo.created_at = $now
SET repo.github_repo_id = r.id,
    repo.full_name = r.full_name,
    repo.url = r.url,
    repo.private = r.private,
    repo.language = coalesce(r.language, repo.language),
    repo.branch = coalesce(repo.branch, r.branch),
    repo.source = coalesce(repo.source, 'github'),
    repo.access_revoked = false,
    repo.last_synced_at = $now
MERGE (i)-[:GRANTS]->(repo)
"""

SYNC_REVOKE_QUERY = """
MATCH (:GitHubInstallation {id: $id, owner: $owner})-[:GRANTS]->(repo:Repository {owner: $owner})
WHERE NOT repo.github_repo_id IN $ids
SET repo.access_revoked = true, repo.selected = false
RETURN count(repo) AS revoked
"""


def _sync_installation(owner: str, installation_id: int, selection: Optional[str]) -> dict:
    try:
        token = github.installation_token(installation_id)["token"]
        granted = github.list_installation_repositories(token)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="GitHub App is not configured")
    except github.GitHubError as error:
        if error.status == 404:
            return {
                "repositories": 0,
                "revoked": _mark_removed(owner, installation_id),
                "uninstalled": True,
            }
        raise HTTPException(status_code=502, detail=error.message)
    repos = [
        {
            "id": item["id"],
            "name": _normalize_key(item["full_name"]).lower(),
            "full_name": item["full_name"],
            "url": item.get("html_url"),
            "private": bool(item.get("private")),
            "language": item.get("language"),
            "branch": item.get("default_branch"),
        }
        for item in granted
    ]

    def work(tx) -> int:
        tx.run(SYNC_RENAME_QUERY, owner=owner, repos=repos).consume()
        tx.run(
            SYNC_UPSERT_QUERY,
            owner=owner,
            id=installation_id,
            repos=repos,
            selected=selection == "selected",
            now=_now(),
        ).consume()
        return tx.run(
            SYNC_REVOKE_QUERY,
            owner=owner,
            id=installation_id,
            ids=[repo["id"] for repo in repos],
        ).single()["revoked"]

    with get_driver().session() as session:
        revoked = session.execute_write(work)
    return {"repositories": len(repos), "revoked": revoked}


@app.post("/github/repositories/refresh")
def refresh_github_repositories(current_user: CurrentUser):
    query = """
    MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {owner: $owner})
    WHERE i.status IN ['active', 'disconnected']
    RETURN i.id AS id, i.repository_selection AS selection, i.status AS status
    """
    with get_driver().session() as session:
        found = list(session.run(query, owner=current_user["id"]))
    installations = [i for i in found if i["status"] == "active"]
    totals = {
        "installations": len(installations),
        "repositories": 0,
        "revoked": 0,
        "uninstalled": 0,
    }
    for paused in (i for i in found if i["status"] == "disconnected"):
        try:
            github.get_installation(paused["id"])
        except RuntimeError:
            raise HTTPException(status_code=503, detail="GitHub App is not configured")
        except github.GitHubError as error:
            if error.status == 404:
                _mark_removed(current_user["id"], paused["id"])
                totals["uninstalled"] += 1
    for installation in installations:
        result = _sync_installation(
            current_user["id"], installation["id"], installation["selection"]
        )
        totals["uninstalled"] += 1 if result.get("uninstalled") else 0
        totals["repositories"] += result["repositories"]
        totals["revoked"] += result["revoked"]
    return totals


@app.get("/github/installations")
def list_github_installations(current_user: CurrentUser):
    query = """
    MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {owner: $owner})
    OPTIONAL MATCH (i)-[:GRANTS]->(repo:Repository {owner: $owner})
    RETURN i { .* } AS installation,
           count(repo) AS repositories,
           sum(CASE WHEN repo.access_revoked = true THEN 1 ELSE 0 END) AS revoked
    ORDER BY installation.account_login
    """
    with get_driver().session() as session:
        return [
            {
                "installation": record["installation"],
                "repositories": record["repositories"],
                "revoked": record["revoked"],
            }
            for record in session.run(query, owner=current_user["id"])
        ]


ACTIVE_INSTALLATIONS = """
MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {owner: $owner})
WHERE i.status = 'active'
RETURN i.id AS id, i.repository_selection AS selection
"""

LISTED_REPOSITORY_NAMES = """
MATCH (repo:Repository {owner: $owner})
RETURN repo.name AS name
"""

SELECT_REPOSITORY = """
MATCH (repo:Repository {owner: $owner, name: $name})
SET repo.selected = true
RETURN repo.name AS name
"""


def _granted_repositories(owner: str) -> list[dict]:
    with get_driver().session() as session:
        installations = list(session.run(ACTIVE_INSTALLATIONS, owner=owner))
    granted = []
    for installation in installations:
        try:
            token = github.installation_token(installation["id"])["token"]
            items = github.list_installation_repositories(token)
        except RuntimeError:
            raise HTTPException(status_code=503, detail="GitHub App is not configured")
        except github.GitHubError as error:
            if error.status == 404:
                _mark_removed(owner, installation["id"])
                continue
            raise HTTPException(status_code=502, detail=error.message)
        granted.append(
            {
                "installation_id": installation["id"],
                "selection": installation["selection"],
                "token": token,
                "items": items,
            }
        )
    return granted


def _find_granted(owner: str, full_name: str) -> Optional[tuple[dict, dict]]:
    wanted = full_name.lower()
    for group in _granted_repositories(owner):
        for item in group["items"]:
            if item["full_name"].lower() == wanted:
                return group, item
    return None


@app.get("/github/available-repositories")
def available_github_repositories(current_user: CurrentUser):
    owner = current_user["id"]
    with get_driver().session() as session:
        listed = {record["name"] for record in session.run(LISTED_REPOSITORY_NAMES, owner=owner)}
    available = []
    for group in _granted_repositories(owner):
        for item in group["items"]:
            if _normalize_key(item["full_name"]).lower() in listed:
                continue
            available.append(
                {
                    "full_name": item["full_name"],
                    "url": item.get("html_url"),
                    "private": bool(item.get("private")),
                    "language": item.get("language"),
                    "branch": item.get("default_branch"),
                }
            )
    return {"repositories": available}


@app.post("/github/repositories", status_code=201)
def add_github_repository(body: GitHubRepositoryIn, current_user: CurrentUser):
    owner = current_user["id"]
    found = _find_granted(owner, body.full_name)
    if found is None:
        raise HTTPException(status_code=404, detail="Repository is not granted to ASPM")
    group, item = found
    _sync_installation(owner, group["installation_id"], group["selection"])
    name = _normalize_key(item["full_name"]).lower()
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(SELECT_REPOSITORY, owner=owner, name=name).single()
        )
    if record is None:
        raise HTTPException(status_code=404, detail="Repository is not granted to ASPM")
    return {"name": record["name"]}


@app.get("/github/branches")
def github_repository_branches(
    current_user: CurrentUser,
    repo: str = Query(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=200),
):
    found = _find_granted(current_user["id"], repo)
    if found is None:
        raise HTTPException(status_code=404, detail="Repository is not granted to ASPM")
    group, item = found
    try:
        branches = github.list_branches(group["token"], item["full_name"])
    except github.GitHubError as error:
        raise HTTPException(status_code=502, detail=error.message)
    return {"branches": branches, "default": item.get("default_branch")}


DISCONNECT_INSTALLATION = """
MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {id: $id, owner: $owner})
SET i.status = 'disconnected', i.updated_at = $now
WITH i
OPTIONAL MATCH (i)-[:GRANTS]->(repo:Repository {owner: $owner})
SET repo.access_revoked = true
RETURN i.id AS id, count(repo) AS revoked
"""

OWNED_INSTALLATION_STATUS = """
MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {id: $id, owner: $owner})
RETURN i.status AS status
"""

OWNED_INSTALLATION = """
MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {id: $id, owner: $owner})
RETURN i.id AS id
"""

MARK_REMOVED = """
MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {id: $id, owner: $owner})
SET i.status = 'removed', i.updated_at = $now
WITH i
OPTIONAL MATCH (i)-[:GRANTS]->(repo:Repository {owner: $owner})
SET repo.access_revoked = true
RETURN i.id AS id, count(repo) AS revoked
"""

FORGET_INSTALLATION = """
MATCH (i:GitHubInstallation {id: $id, owner: $owner, status: 'removed'})
DETACH DELETE i
"""

FORGET_STALE_INSTALLATIONS = """
MATCH (i:GitHubInstallation {owner: $owner, status: 'removed', account_login: $login})
WHERE i.id <> $id
DETACH DELETE i
"""

REACTIVATE_INSTALLATION = """
MATCH (:User {id: $owner})-[:HAS_INSTALLATION]->(i:GitHubInstallation {id: $id, owner: $owner})
SET i.account_login = $login,
    i.account_type = $account_type,
    i.repository_selection = $selection,
    i.status = $status,
    i.updated_at = $now
RETURN i { .* } AS installation
"""


def _mark_removed(owner: str, installation_id: int) -> int:
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(MARK_REMOVED, owner=owner, id=installation_id, now=_now()).single()
        )
    return record["revoked"] if record else 0


@app.delete("/github/installations/{installation_id}")
def disconnect_github_installation(installation_id: int, current_user: CurrentUser):
    with get_driver().session() as session:
        state = session.run(
            OWNED_INSTALLATION_STATUS, owner=current_user["id"], id=installation_id
        ).single()
    if state is not None and state["status"] == "removed":
        with get_driver().session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    FORGET_INSTALLATION, owner=current_user["id"], id=installation_id
                ).consume()
            )
        return {"forgotten": installation_id}
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(
                DISCONNECT_INSTALLATION, owner=current_user["id"], id=installation_id, now=_now()
            ).single()
        )
    if record is None:
        raise HTTPException(status_code=404, detail="Installation not found")
    return {"disconnected": installation_id, "revoked": record["revoked"]}


@app.post("/github/installations/{installation_id}/reconnect")
def reconnect_github_installation(installation_id: int, current_user: CurrentUser):
    owner = current_user["id"]
    with get_driver().session() as session:
        owned = session.run(OWNED_INSTALLATION, owner=owner, id=installation_id).single()
    if owned is None:
        raise HTTPException(status_code=404, detail="Installation not found")
    try:
        details = github.get_installation(installation_id)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="GitHub App is not configured")
    except github.GitHubError as error:
        if error.status == 404:
            _mark_removed(owner, installation_id)
            raise HTTPException(status_code=404, detail="Installation not found")
        raise HTTPException(status_code=502, detail=error.message)
    account = details.get("account") or {}
    status = "suspended" if details.get("suspended_at") else "active"
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(
                REACTIVATE_INSTALLATION,
                owner=owner,
                id=installation_id,
                login=account.get("login"),
                account_type=account.get("type"),
                selection=details.get("repository_selection"),
                status=status,
                now=_now(),
            ).single()
        )
    synced = (
        _sync_installation(owner, installation_id, details.get("repository_selection"))
        if status == "active"
        else None
    )
    return {"installation": record["installation"], "sync": synced}


@app.get("/graph", dependencies=signed_in)
def get_graph(
    current_user: CurrentUser,
    status: str = ",".join(ACTIVE_STATUSES),
    severity: Optional[str] = Query(None, max_length=100),
    priority: Optional[str] = Query(None, max_length=100),
    environment: Optional[str] = Query(None, max_length=200),
    internet_facing: Optional[bool] = None,
    scanner: Optional[str] = Query(None, max_length=200),
    repo: Optional[str] = Query(None, max_length=500),
):
    if any((severity, priority, environment, scanner, repo)) or internet_facing is not None:
        filtered_nodes: dict[str, dict] = {}
        filtered_links: dict[tuple, dict] = {}
        for finding in _query_findings(
            current_user["id"], status, None, severity, priority, environment, internet_facing, scanner, repo
        ):
            chain = [
                ("Repository", finding["repository"], "name"),
                ("Vulnerability", finding["vulnerability"], "id"),
            ]
            if finding["asset"]:
                chain.append(("Asset", finding["asset"], "name"))
            ids = []
            for label, props, key in chain:
                node = f"{label}:{props[key]}"
                filtered_nodes.setdefault(node, {"id": node, "label": label, "properties": props})
                ids.append(node)
            for (source, target), rel in zip(zip(ids, ids[1:]), ("CONTAINS", "AFFECTS")):
                filtered_links[(source, target, rel)] = {
                    "source": source,
                    "target": target,
                    "type": rel,
                }
        return {"nodes": list(filtered_nodes.values()), "links": list(filtered_links.values())}

    query = """
    MATCH (n {owner: $owner})
    WHERE n:Repository OR n:Asset
       OR (n:Vulnerability AND ($statuses IS NULL OR n.status IN $statuses))
    OPTIONAL MATCH (n)-[r:CONTAINS|AFFECTS]->(m)
    WHERE NOT m:Vulnerability OR $statuses IS NULL OR m.status IN $statuses
    RETURN n, labels(n)[0] AS label, type(r) AS rel, m, labels(m)[0] AS target_label
    """
    key_for = {"Repository": "name", "Vulnerability": "id", "Asset": "name"}

    def node_id(label: str, props: dict) -> str:
        return f"{label}:{props[key_for[label]]}"

    nodes: dict[str, dict] = {}
    links: list[dict] = []
    db = get_driver()
    with db.session() as session:
        for record in session.run(
            query, owner=current_user["id"], statuses=_parse_statuses(status)
        ):
            props = dict(record["n"])
            source = node_id(record["label"], props)
            nodes.setdefault(source, {"id": source, "label": record["label"], "properties": props})
            if record["rel"] is not None:
                target = node_id(record["target_label"], dict(record["m"]))
                links.append({"source": source, "target": target, "type": record["rel"]})

    return {"nodes": list(nodes.values()), "links": links}


@app.post("/scans/failed", status_code=201, dependencies=protected)
def record_failed_scan(failure: ScanFailureIn, owner: Owner):
    repository = RepositoryIn(name=failure.repo_name, url=failure.repo_url)
    require_known_repository(owner, repository)
    scan_id = uuid4().hex
    now = _now()
    query = """
    MERGE (repo:Repository {owner: $owner, name: $repo.name})
      ON CREATE SET repo.url = $repo.url
    CREATE (s:Scan {id: $scan_id, owner: $owner, scanner: $scanner, status: 'failed',
                    started_at: $now, finished_at: $now, commit: $commit,
                    error: $error, detail: $detail, partial: false,
                    ingested: 0, resolved: 0, reopened: 0, skipped: 0})
    MERGE (s)-[:SCANNED]->(repo)
    """
    with get_driver().session() as session:
        session.execute_write(
            lambda tx: tx.run(
                query,
                owner=owner,
                repo=repository.model_dump(),
                scan_id=scan_id,
                scanner=failure.scanner,
                now=now,
                commit=failure.commit,
                error=failure.error,
                detail=failure.detail,
            ).consume()
        )
    return {"scan_id": scan_id, "status": "failed"}


SCAN_JOB_PROJECTION = (
    "job { .id, .repository_name, .status, .scanners, .requested_at, .requested_by }"
)

SCAN_JOB_STATE = """
MATCH (repo:Repository {owner: $owner, name: $name})
OPTIONAL MATCH (repo)-[:HAS_JOB]->(done:ScanJob {owner: $owner, status: 'done'})
RETURN coalesce(repo.access_revoked, false) AS revoked, max(done.requested_at) AS last_done
"""

QUEUE_SCAN_JOB = f"""
MATCH (repo:Repository {{owner: $owner, name: $name}})
CREATE (repo)-[:HAS_JOB]->(job:ScanJob {{
  id: $id, owner: $owner, repository_name: repo.name, active_repository: repo.name,
  status: 'queued', scanners: $scanners, requested_at: $now, requested_by: $owner
}})
SET repo.last_scan_requested_at = $now
RETURN {SCAN_JOB_PROJECTION} AS job
"""


@app.post("/scans/run", status_code=201)
def queue_scan(body: ScanRunIn, current_user: CurrentUser):
    owner = current_user["id"]
    with get_driver().session() as session:
        state = session.run(SCAN_JOB_STATE, owner=owner, name=body.repository).single()
    if state is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    if state["revoked"]:
        raise HTTPException(status_code=409, detail="Repository access was revoked on GitHub")
    if state["last_done"]:
        next_allowed = datetime.fromisoformat(state["last_done"]) + timedelta(days=SCAN_COOLDOWN_DAYS)
        wait = next_allowed - datetime.now(timezone.utc)
        if wait.total_seconds() > 0:
            raise HTTPException(
                status_code=429,
                detail={"message": "Repository was scanned recently", "next_allowed_at": next_allowed.isoformat()},
                headers={"Retry-After": str(int(wait.total_seconds()) + 1)},
            )
    try:
        with get_driver().session() as session:
            record = session.execute_write(
                lambda tx: tx.run(
                    QUEUE_SCAN_JOB,
                    owner=owner,
                    name=body.repository,
                    id=uuid4().hex,
                    scanners=body.scanners,
                    now=_now(),
                ).single()
            )
    except ConstraintError:
        raise HTTPException(status_code=409, detail="A scan is already queued for this repository")
    if record is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    return {"job": record["job"]}


@app.get("/scans/failing", dependencies=signed_in)
def list_failing_scans(current_user: CurrentUser):
    query = """
    MATCH (s:Scan {owner: $owner})-[:SCANNED]->(repo:Repository {owner: $owner})
    WITH repo, s ORDER BY s.started_at DESC
    WITH repo, s.scanner AS scanner, collect(s)[0] AS latest
    WHERE latest.status = 'failed'
    RETURN repo.name AS repository,
           scanner,
           latest.started_at AS failed_at,
           latest.error AS error,
           repo.last_scanned_at AS last_succeeded_at
    ORDER BY failed_at DESC
    """
    with get_driver().session() as session:
        return [record.data() for record in session.run(query, owner=current_user["id"])]


@app.get("/scans", dependencies=signed_in)
def list_scans(
    current_user: CurrentUser, repo: Optional[str] = None, limit: int = Query(50, ge=1, le=500)
):
    query = """
    MATCH (s:Scan {owner: $owner})-[:SCANNED]->(repo:Repository {owner: $owner})
    WHERE $repo IS NULL OR repo.name = $repo
    RETURN s { .*, repository: repo.name } AS scan
    ORDER BY s.started_at DESC
    LIMIT $limit
    """
    with get_driver().session() as session:
        return [
            record["scan"]
            for record in session.run(
                query,
                owner=current_user["id"],
                repo=_normalize_key(repo).lower() if repo and repo.strip() else None,
                limit=limit,
            )
        ]


def _load_image_asset(owner: str, params: IngestParams, report: trivy.TrivyReport) -> AssetIn:
    if not params.asset_name:
        raise HTTPException(status_code=422, detail="asset_name is required in image mode")
    with get_driver().session() as session:
        record = session.run(
            "MATCH (a:Asset {owner: $owner, name: $name}) RETURN a { .* } AS asset",
            owner=owner,
            name=params.asset_name,
        ).single()
    if record is None:
        raise HTTPException(status_code=422, detail=f"Unknown asset '{params.asset_name}'")
    node = record["asset"]
    if not node.get("image"):
        raise HTTPException(
            status_code=422, detail=f"Asset '{params.asset_name}' has no image in the catalog"
        )
    if report.ArtifactName != node["image"]:
        raise HTTPException(
            status_code=422,
            detail=f"Report is for '{report.ArtifactName}', asset image is '{node['image']}'",
        )
    return AssetIn(**node)


def _ingest_scan(
    owner: str, params: IngestParams, scanner: str, type: str, parse, report, image: bool = False
) -> dict:
    repository = RepositoryIn(
        name=params.repo_name, url=params.repo_url, language=params.repo_language
    )
    require_known_repository(owner, repository)
    if image:
        asset = _load_image_asset(owner, params, report)
        id_prefix = f"{repository.name}:{asset.name}:image"
    else:
        asset_fields = (params.asset_name, params.asset_environment, params.asset_type)
        if any(asset_fields) and not all(asset_fields):
            raise HTTPException(
                status_code=422,
                detail="asset_name, asset_environment and asset_type must be given together",
            )
        asset = (
            AssetIn(
                name=params.asset_name,
                environment=params.asset_environment,
                type=params.asset_type,
                internet_facing=params.asset_internet_facing,
            )
            if params.asset_name
            else None
        )
        id_prefix = repository.name

    findings, skipped = parse(report, id_prefix)

    result = run_scan(
        owner,
        repository,
        asset,
        scanner,
        type,
        [f.model_dump() for f in findings],
        params.commit,
        params.partial,
        skipped,
        image,
    )
    return {**result, "ids": [f.id for f in findings]}


@app.post("/ingest/trivy", status_code=201, dependencies=protected)
def ingest_trivy(
    report: trivy.TrivyReport, params: Annotated[TrivyIngestParams, Query()], owner: Owner
):
    if params.mode == "image":
        return _ingest_scan(owner, params, "trivy-image", "container", trivy.parse, report, True)
    return _ingest_scan(owner, params, "trivy", "sca", trivy.parse, report)


@app.post("/ingest/semgrep", status_code=201, dependencies=protected)
def ingest_semgrep(
    report: semgrep.SemgrepReport, params: Annotated[IngestParams, Query()], owner: Owner
):
    return _ingest_scan(owner, params, "semgrep", "sast", semgrep.parse, report)
