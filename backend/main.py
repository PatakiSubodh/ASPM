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
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional
from uuid import uuid4

import yaml
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from neo4j import GraphDatabase, Driver
from pydantic import BaseModel, Field, field_validator, model_validator

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "aspm_dev_password")
ASPM_API_KEY = os.getenv("ASPM_API_KEY", "")
CATALOG_PATH = os.getenv("CATALOG_PATH", "/app/catalog.yaml")

driver: Optional[Driver] = None


# ---------------------------------------------------------------------------
# Neo4j connection lifecycle
# ---------------------------------------------------------------------------

def get_driver() -> Driver:
    if driver is None:
        raise HTTPException(status_code=503, detail="Neo4j driver not initialized")
    return driver


CONSTRAINTS = [
    "CREATE CONSTRAINT repository_name_unique IF NOT EXISTS "
    "FOR (r:Repository) REQUIRE r.name IS UNIQUE",
    "CREATE CONSTRAINT vulnerability_id_unique IF NOT EXISTS "
    "FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
    "CREATE CONSTRAINT asset_name_unique IF NOT EXISTS "
    "FOR (a:Asset) REQUIRE a.name IS UNIQUE",
    "CREATE CONSTRAINT scan_id_unique IF NOT EXISTS "
    "FOR (s:Scan) REQUIRE s.id IS UNIQUE",
]


def ensure_constraints(db: Driver) -> None:
    with db.session() as session:
        for statement in CONSTRAINTS:
            session.run(statement).consume()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global driver
    if not ASPM_API_KEY:
        raise RuntimeError("ASPM_API_KEY is not set")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    ensure_constraints(driver)
    load_catalog_file(driver)
    yield
    driver.close()


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


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
def _normalize_key(value: str) -> str:
    value = " ".join(value.split())
    if not value:
        raise ValueError("must not be blank")
    return value


class RepositoryIn(BaseModel):
    name: str
    url: Optional[str] = None
    language: Optional[str] = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class VulnerabilityIn(BaseModel):
    id: str
    cve: Optional[str] = None
    severity: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    description: str

    @field_validator("id")
    @classmethod
    def normalize_id(cls, v: str) -> str:
        return _normalize_key(v).upper()


class AssetIn(BaseModel):
    name: str
    environment: str
    type: str
    internet_facing: bool = False

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class FindingIngest(BaseModel):
    repository: RepositoryIn
    vulnerability: VulnerabilityIn
    asset: Optional[AssetIn] = None


class CatalogRepository(BaseModel):
    name: str
    url: str
    language: Optional[str] = None
    branch: Optional[str] = None
    assets: list[AssetIn] = []

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class CatalogIn(BaseModel):
    repositories: list[CatalogRepository] = []

    @model_validator(mode="after")
    def unique_repositories(self) -> "CatalogIn":
        names = [r.name for r in self.repositories]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate repositories: {', '.join(duplicates)}")
        return self


class TrivyVulnerability(BaseModel):
    VulnerabilityID: str
    PkgName: str
    InstalledVersion: str = ""
    FixedVersion: Optional[str] = None
    Severity: str
    Title: Optional[str] = None
    Description: Optional[str] = None


class TrivyResult(BaseModel):
    Target: str
    Vulnerabilities: Optional[list[TrivyVulnerability]] = None


class TrivyReport(BaseModel):
    Results: Optional[list[TrivyResult]] = None


class TrivyIngestParams(BaseModel):
    repo_name: str
    repo_url: Optional[str] = None
    repo_language: Optional[str] = None
    asset_name: Optional[str] = None
    asset_environment: Optional[str] = None
    asset_type: Optional[str] = None
    asset_internet_facing: bool = False
    commit: Optional[str] = None
    partial: bool = False

    @field_validator("repo_name", "asset_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


FindingStatus = Literal["open", "in_progress", "resolved", "accepted_risk", "false_positive"]
STATUSES: tuple[str, ...] = FindingStatus.__args__
ACTIVE_STATUSES = ["open", "in_progress"]


class StatusUpdate(BaseModel):
    status: FindingStatus


class ScanFailureIn(BaseModel):
    repo_name: str
    repo_url: Optional[str] = None
    scanner: str = Field(pattern="^[a-z0-9_-]+$")
    commit: Optional[str] = None
    error: str = Field(min_length=1, max_length=200)
    detail: Optional[str] = Field(default=None, max_length=500)

    @field_validator("repo_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


ASSET_UPSERT_QUERY = """
MERGE (asset:Asset {name: $asset.name})
  ON CREATE SET
    asset.environment = $asset.environment,
    asset.type = $asset.type,
    asset.internet_facing = $asset.internet_facing
"""

INGEST_BATCH_QUERY = """
MERGE (repo:Repository {name: $repo.name})
  ON CREATE SET repo.url = $repo.url, repo.language = $repo.language
WITH repo
OPTIONAL MATCH (explicit:Asset {name: $asset_name})
UNWIND $findings AS f
MERGE (vuln:Vulnerability {id: f.id})
  ON CREATE SET vuln.status = 'open', vuln.first_seen = $now
WITH repo, explicit, f, vuln, vuln.status = 'resolved' AS reopened
SET vuln.cve = f.cve,
    vuln.severity = f.severity,
    vuln.description = f.description,
    vuln.package = f.package,
    vuln.installed_version = f.installed_version,
    vuln.fixed_version = f.fixed_version,
    vuln.location = f.location,
    vuln.scanner = $scanner,
    vuln.type = $type,
    vuln.last_seen = $now,
    vuln.last_scan_id = $scan_id,
    vuln.status = CASE WHEN reopened THEN 'open' ELSE vuln.status END,
    vuln.reopened_at = CASE WHEN reopened THEN $now ELSE vuln.reopened_at END,
    vuln.resolved_at = CASE WHEN reopened THEN null ELSE vuln.resolved_at END
MERGE (repo)-[:CONTAINS]->(vuln)
WITH repo, explicit, vuln, reopened
CALL (vuln, explicit) {
  WITH vuln, explicit WHERE explicit IS NOT NULL
  MERGE (vuln)-[affects:AFFECTS]->(explicit)
  SET affects.source = 'ingest'
}
CALL (repo, vuln) {
  MATCH (repo)-[:DEPLOYS_TO]->(deployed:Asset)
  MERGE (vuln)-[affects:AFFECTS]->(deployed)
    ON CREATE SET affects.source = 'catalog'
}
RETURN count(vuln) AS ingested, sum(CASE WHEN reopened THEN 1 ELSE 0 END) AS reopened
"""

AUTO_RESOLVE_QUERY = """
MATCH (:Repository {name: $repo})-[:CONTAINS]->(v:Vulnerability {scanner: $scanner})
WHERE v.status IN ['open', 'in_progress'] AND v.last_scan_id <> $scan_id
SET v.status = 'resolved', v.resolved_at = $now
RETURN count(v) AS resolved
"""


def ingest_batch(
    tx,
    repo: RepositoryIn,
    asset: Optional[AssetIn],
    scanner: str,
    scan_id: Optional[str],
    findings: list[dict],
    now: str,
    type: Optional[str] = None,
) -> dict:
    if asset is not None:
        tx.run(ASSET_UPSERT_QUERY, asset=asset.model_dump()).consume()
    record = tx.run(
        INGEST_BATCH_QUERY,
        repo=repo.model_dump(),
        asset_name=asset.name if asset else None,
        scanner=scanner,
        scan_id=scan_id,
        type=type,
        findings=findings,
        now=now,
    ).single()
    return {"ingested": record["ingested"], "reopened": record["reopened"]}


def run_scan(
    repo: RepositoryIn,
    asset: Optional[AssetIn],
    scanner: str,
    type: str,
    findings: list[dict],
    commit: Optional[str],
    partial: bool,
    skipped: int,
) -> dict:
    scan_id = uuid4().hex
    started_at = _now()

    def work(tx) -> dict:
        tx.run(
            """
            MERGE (repo:Repository {name: $repo.name})
              ON CREATE SET repo.url = $repo.url, repo.language = $repo.language
            CREATE (s:Scan {id: $scan_id, scanner: $scanner, started_at: $now,
                            commit: $commit, partial: $partial})
            MERGE (s)-[:SCANNED]->(repo)
            """,
            repo=repo.model_dump(),
            scan_id=scan_id,
            scanner=scanner,
            now=started_at,
            commit=commit,
            partial=partial,
        ).consume()
        counts = ingest_batch(tx, repo, asset, scanner, scan_id, findings, started_at, type)
        resolved = 0
        if not partial:
            resolved = tx.run(
                AUTO_RESOLVE_QUERY,
                repo=repo.name,
                scanner=scanner,
                scan_id=scan_id,
                now=started_at,
            ).single()["resolved"]
        finished_at = _now()
        tx.run(
            """
            MATCH (s:Scan {id: $scan_id})-[:SCANNED]->(repo:Repository)
            SET s.finished_at = $now,
                s.status = 'succeeded',
                s.ingested = $ingested,
                s.resolved = $resolved,
                s.reopened = $reopened,
                s.skipped = $skipped,
                repo.last_scanned_at = $now
            """,
            scan_id=scan_id,
            now=finished_at,
            ingested=counts["ingested"],
            resolved=resolved,
            reopened=counts["reopened"],
            skipped=skipped,
        ).consume()
        return {"scan_id": scan_id, **counts, "resolved": resolved, "skipped": skipped}

    with get_driver().session() as session:
        return session.execute_write(work)


def require_known_repository(repo: RepositoryIn) -> None:
    if repo.url:
        return
    with get_driver().session() as session:
        exists = session.run(
            "MATCH (r:Repository {name: $name}) RETURN count(r) > 0 AS exists",
            name=repo.name,
        ).single()["exists"]
    if not exists:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown repository '{repo.name}': add it to the catalog or pass its url",
        )


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


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
ENVIRONMENT_WEIGHT = {
    "production": 1.0,
    "prod": 1.0,
    "staging": 0.6,
    "stage": 0.6,
    "uat": 0.6,
    "qa": 0.6,
    "development": 0.3,
    "dev": 0.3,
    "test": 0.3,
}
DEFAULT_ENVIRONMENT_WEIGHT = 0.6
INTERNET_FACING_WEIGHT = 1.5
MAX_RISK = SEVERITY_WEIGHT["CRITICAL"] * ENVIRONMENT_WEIGHT["production"] * INTERNET_FACING_WEIGHT
PRIORITY_BANDS = ((70, "P1"), (40, "P2"), (20, "P3"), (0, "P4"))


def risk_score(severity: str, environment: Optional[str], internet_facing: bool) -> dict:
    severity_weight = SEVERITY_WEIGHT.get(severity, SEVERITY_WEIGHT["LOW"])
    environment_weight = ENVIRONMENT_WEIGHT.get(
        (environment or "").strip().lower(), DEFAULT_ENVIRONMENT_WEIGHT
    )
    exposure_weight = INTERNET_FACING_WEIGHT if internet_facing else 1.0
    score = min(100, round(severity_weight * environment_weight * exposure_weight / MAX_RISK * 100))
    priority = next(p for threshold, p in PRIORITY_BANDS if score >= threshold)
    return {
        "score": score,
        "priority": priority,
        "factors": {
            "severity": severity_weight,
            "environment": environment_weight,
            "exposure": exposure_weight,
        },
    }


def asset_risk(severity: str, asset: dict) -> dict:
    return risk_score(severity, asset.get("environment"), bool(asset.get("internet_facing")))


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


def _trivy_description(vuln: TrivyVulnerability, target: str) -> str:
    title = vuln.Title or vuln.Description or vuln.VulnerabilityID
    fix = f"fixed in {vuln.FixedVersion}" if vuln.FixedVersion else "no fix available"
    return f"{title} ({vuln.PkgName} {vuln.InstalledVersion}, {fix}; {target})"


@app.post("/ingest/trivy", status_code=201, dependencies=protected)
def ingest_trivy(report: TrivyReport, params: Annotated[TrivyIngestParams, Query()]):
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

    findings: dict[str, dict] = {}
    skipped = 0
    for result in report.Results or []:
        for vuln in result.Vulnerabilities or []:
            if vuln.Severity not in SEVERITIES:
                skipped += 1
                continue
            vuln_id = _normalize_key(f"{repository.name}:{vuln.PkgName}:{vuln.VulnerabilityID}").upper()
            findings[vuln_id] = {
                "id": vuln_id,
                "cve": vuln.VulnerabilityID if vuln.VulnerabilityID.upper().startswith("CVE-") else None,
                "severity": vuln.Severity,
                "description": _trivy_description(vuln, result.Target),
                "package": vuln.PkgName,
                "installed_version": vuln.InstalledVersion,
                "fixed_version": vuln.FixedVersion,
                "location": result.Target,
            }

    result = run_scan(
        repository,
        asset,
        "trivy",
        "sca",
        list(findings.values()),
        params.commit,
        params.partial,
        skipped,
    )
    return {**result, "ids": list(findings)}
