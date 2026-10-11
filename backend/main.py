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
from pathlib import Path
from typing import Annotated, Optional
from uuid import uuid4

import yaml
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from neo4j import Driver

from connectors import trivy
from db import close_driver, connect_driver, get_driver
from ingest import _now, ingest_batch, require_known_repository, run_scan
from models import (
    ACTIVE_STATUSES,
    STATUSES,
    AssetIn,
    CatalogIn,
    FindingIngest,
    RepositoryIn,
    ScanFailureIn,
    StatusUpdate,
    TrivyIngestParams,
    _normalize_key,
)
from risk import SEVERITIES, asset_risk

load_dotenv()

ASPM_API_KEY = os.getenv("ASPM_API_KEY", "")
CATALOG_PATH = os.getenv("CATALOG_PATH", "/app/catalog.yaml")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ASPM_API_KEY:
        raise RuntimeError("ASPM_API_KEY is not set")
    load_catalog_file(connect_driver())
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


protected = [Depends(require_api_key)]


def _parse_statuses(status: str) -> Optional[list[str]]:
    if status.strip().lower() == "all":
        return None
    statuses = [s.strip().lower() for s in status.split(",") if s.strip()]
    invalid = [s for s in statuses if s not in STATUSES]
    if invalid or not statuses:
        raise HTTPException(status_code=422, detail=f"Invalid status filter: {status}")
    return statuses


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


CATALOG_UPSERT_QUERY = """
UNWIND $repositories AS r
MERGE (repo:Repository {name: r.name})
SET repo.url = r.url,
    repo.language = coalesce(r.language, repo.language),
    repo.branch = coalesce(r.branch, repo.branch)
WITH repo, r
UNWIND r.assets AS a
MERGE (asset:Asset {name: a.name})
SET asset.environment = a.environment,
    asset.type = a.type,
    asset.internet_facing = a.internet_facing,
    asset.source = 'catalog'
MERGE (repo)-[deploys:DEPLOYS_TO]->(asset)
  ON CREATE SET deploys.source = 'catalog'
"""

CATALOG_PRUNE_QUERY = """
UNWIND $repositories AS r
MATCH (repo:Repository {name: r.name})-[deploys:DEPLOYS_TO {source: 'catalog'}]->(asset:Asset)
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
MATCH (repo:Repository {name: r.name})-[:DEPLOYS_TO]->(asset:Asset)
MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
MERGE (vuln)-[affects:AFFECTS]->(asset)
  ON CREATE SET affects.source = 'catalog'
"""


def apply_catalog(tx, catalog: CatalogIn) -> dict:
    repositories = [r.model_dump() for r in catalog.repositories]
    linked = tx.run(CATALOG_UPSERT_QUERY, repositories=repositories).consume().counters
    unlinked = tx.run(CATALOG_PRUNE_QUERY, repositories=repositories).single()["unlinked"]
    backfilled = tx.run(CATALOG_BACKFILL_QUERY, repositories=repositories).consume().counters
    return {
        "repositories": len(repositories),
        "assets": len({a["name"] for r in repositories for a in r["assets"]}),
        "linked": linked.relationships_created,
        "unlinked": unlinked,
        "backfilled": backfilled.relationships_created,
    }


def load_catalog_file(db: Driver) -> None:
    path = Path(CATALOG_PATH)
    if not path.is_file():
        return
    catalog = CatalogIn.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    with db.session() as session:
        session.execute_write(apply_catalog, catalog)


@app.post("/catalog", dependencies=protected)
def upsert_catalog(catalog: CatalogIn):
    with get_driver().session() as session:
        return session.execute_write(apply_catalog, catalog)


@app.get("/catalog", dependencies=protected)
def get_catalog():
    query = """
    MATCH (repo:Repository)
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
            for record in session.run(query, statuses=ACTIVE_STATUSES)
        ]


@app.post("/findings", status_code=201, dependencies=protected)
def ingest_finding(finding: FindingIngest):
    vuln = finding.vulnerability
    require_known_repository(finding.repository)
    with get_driver().session() as session:
        session.execute_write(
            ingest_batch,
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


@app.patch("/findings/{finding_id}", dependencies=protected)
def update_finding_status(finding_id: str, update: StatusUpdate):
    query = """
    MATCH (vuln:Vulnerability {id: $id})
    WITH vuln, vuln.status = $status AS unchanged
    SET vuln.status = $status,
        vuln.status_changed_at = CASE WHEN unchanged THEN vuln.status_changed_at ELSE $now END,
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
                id=" ".join(finding_id.split()).upper(),
                status=update.status,
                now=_now(),
            ).single()
        )
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"vulnerability": record["vulnerability"]}


@app.get("/findings", dependencies=protected)
def list_findings(status: str = ",".join(ACTIVE_STATUSES)):
    """Return every repository -> vulnerability -> asset chain in the graph."""
    query = """
    MATCH (repo:Repository)-[:CONTAINS]->(vuln:Vulnerability)
    WHERE $statuses IS NULL OR vuln.status IN $statuses
    OPTIONAL MATCH (vuln)-[:AFFECTS]->(asset:Asset)
    RETURN repo { .* } AS repository, vuln { .* } AS vulnerability, asset { .* } AS asset
    """
    db = get_driver()
    with db.session() as session:
        findings = [
            {
                "repository": record["repository"],
                "vulnerability": record["vulnerability"],
                "asset": record["asset"],
                "risk": asset_risk(record["vulnerability"]["severity"], record["asset"] or {}),
            }
            for record in session.run(query, statuses=_parse_statuses(status))
        ]
    return sorted(findings, key=lambda f: f["risk"]["score"], reverse=True)


@app.get("/findings/{finding_id}", dependencies=protected)
def get_finding(finding_id: str):
    query = """
    MATCH (vuln:Vulnerability {id: $id})
    OPTIONAL MATCH (repo:Repository)-[:CONTAINS]->(vuln)
    WITH vuln, collect(DISTINCT repo { .* }) AS repositories
    OPTIONAL MATCH (vuln)-[:AFFECTS]->(asset:Asset)
    RETURN vuln { .* } AS vulnerability, repositories, collect(DISTINCT asset { .* }) AS assets
    """
    db = get_driver()
    with db.session() as session:
        record = session.run(query, id=" ".join(finding_id.split()).upper()).single()

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


@app.get("/assets", dependencies=protected)
def list_assets():
    query = """
    MATCH (asset:Asset)
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
            for record in session.run(query, statuses=ACTIVE_STATUSES)
        ]


@app.get("/graph", dependencies=protected)
def get_graph(status: str = ",".join(ACTIVE_STATUSES)):
    query = """
    MATCH (n)
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
        for record in session.run(query, statuses=_parse_statuses(status)):
            props = dict(record["n"])
            source = node_id(record["label"], props)
            nodes.setdefault(source, {"id": source, "label": record["label"], "properties": props})
            if record["rel"] is not None:
                target = node_id(record["target_label"], dict(record["m"]))
                links.append({"source": source, "target": target, "type": record["rel"]})

    return {"nodes": list(nodes.values()), "links": links}


@app.post("/scans/failed", status_code=201, dependencies=protected)
def record_failed_scan(failure: ScanFailureIn):
    repository = RepositoryIn(name=failure.repo_name, url=failure.repo_url)
    require_known_repository(repository)
    scan_id = uuid4().hex
    now = _now()
    query = """
    MERGE (repo:Repository {name: $repo.name})
      ON CREATE SET repo.url = $repo.url
    CREATE (s:Scan {id: $scan_id, scanner: $scanner, status: 'failed',
                    started_at: $now, finished_at: $now, commit: $commit,
                    error: $error, detail: $detail, partial: false,
                    ingested: 0, resolved: 0, reopened: 0, skipped: 0})
    MERGE (s)-[:SCANNED]->(repo)
    """
    with get_driver().session() as session:
        session.execute_write(
            lambda tx: tx.run(
                query,
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


@app.get("/scans/failing", dependencies=protected)
def list_failing_scans():
    query = """
    MATCH (s:Scan)-[:SCANNED]->(repo:Repository)
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
        return [record.data() for record in session.run(query)]


@app.get("/scans", dependencies=protected)
def list_scans(repo: Optional[str] = None, limit: int = Query(50, ge=1, le=500)):
    query = """
    MATCH (s:Scan)-[:SCANNED]->(repo:Repository)
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
                repo=_normalize_key(repo).lower() if repo and repo.strip() else None,
                limit=limit,
            )
        ]


@app.post("/ingest/trivy", status_code=201, dependencies=protected)
def ingest_trivy(report: trivy.TrivyReport, params: Annotated[TrivyIngestParams, Query()]):
    repository = RepositoryIn(
        name=params.repo_name, url=params.repo_url, language=params.repo_language
    )
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
    require_known_repository(repository)

    findings, skipped = trivy.parse(report, repository.name)

    result = run_scan(
        repository,
        asset,
        "trivy",
        "sca",
        [f.model_dump() for f in findings],
        params.commit,
        params.partial,
        skipped,
    )
    return {**result, "ids": [f.id for f in findings]}
