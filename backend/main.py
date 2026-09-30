"""
ASPM Backend — FastAPI service backed by Neo4j.

Graph model:
    (:Repository)-[:CONTAINS]->(:Vulnerability)-[:AFFECTS]->(:Asset)

This lets us answer the core ASPM question: "which production assets are
exposed by which vulnerable code, and where did that vulnerability come from?"
"""

import os
from contextlib import asynccontextmanager
from typing import Annotated, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase, Driver
from pydantic import BaseModel, Field, field_validator

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "aspm_dev_password")

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
]


def ensure_constraints(db: Driver) -> None:
    with db.session() as session:
        for statement in CONSTRAINTS:
            session.run(statement).consume()


def seed_sample_data(db: Driver) -> None:
    """Idempotently create a dummy repo -> vulnerability -> asset chain so the
    UI has real graph data to render immediately."""
    query = """
    MERGE (repo:Repository {name: $repo_name})
      ON CREATE SET repo.url = $repo_url, repo.language = $repo_language

    MERGE (vuln:Vulnerability {id: $vuln_id})
      ON CREATE SET
        vuln.cve = $vuln_cve,
        vuln.severity = $vuln_severity,
        vuln.description = $vuln_description,
        vuln.status = $vuln_status

    MERGE (asset:Asset {name: $asset_name})
      ON CREATE SET
        asset.environment = $asset_environment,
        asset.type = $asset_type,
        asset.internet_facing = $asset_internet_facing

    MERGE (repo)-[:CONTAINS]->(vuln)
    MERGE (vuln)-[:AFFECTS]->(asset)
    """
    with db.session() as session:
        session.run(
            query,
            repo_name="payments-service",
            repo_url="https://github.com/example-org/payments-service",
            repo_language="Python",
            vuln_id="VULN-1001",
            vuln_cve="CVE-2024-12345",
            vuln_severity="CRITICAL",
            vuln_description="SQL Injection in the /invoices search endpoint due to unsanitized query parameter concatenation.",
            vuln_status="open",
            asset_name="prod-payments-api",
            asset_environment="production",
            asset_type="Kubernetes Service",
            asset_internet_facing=True,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global driver
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    ensure_constraints(driver)
    seed_sample_data(driver)
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
    url: str
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
    status: str = "open"

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
    asset: AssetIn


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
    repo_url: str
    repo_language: Optional[str] = None
    asset_name: str
    asset_environment: str
    asset_type: str
    asset_internet_facing: bool = False

    @field_validator("repo_name", "asset_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/findings", status_code=201)
def ingest_finding(finding: FindingIngest):
    """Ingest a security finding: links a repository to a vulnerability to
    the production asset it exposes, merging into the existing graph."""
    query = """
    MERGE (repo:Repository {name: $repo_name})
      ON CREATE SET repo.url = $repo_url, repo.language = $repo_language

    MERGE (vuln:Vulnerability {id: $vuln_id})
      SET
        vuln.cve = $vuln_cve,
        vuln.severity = $vuln_severity,
        vuln.description = $vuln_description,
        vuln.status = $vuln_status

    MERGE (asset:Asset {name: $asset_name})
      ON CREATE SET
        asset.environment = $asset_environment,
        asset.type = $asset_type,
        asset.internet_facing = $asset_internet_facing

    MERGE (repo)-[:CONTAINS]->(vuln)
    MERGE (vuln)-[:AFFECTS]->(asset)
    RETURN repo.name AS repository, vuln.id AS vulnerability, asset.name AS asset
    """
    db = get_driver()
    with db.session() as session:
        record = session.run(
            query,
            repo_name=finding.repository.name,
            repo_url=finding.repository.url,
            repo_language=finding.repository.language,
            vuln_id=finding.vulnerability.id,
            vuln_cve=finding.vulnerability.cve,
            vuln_severity=finding.vulnerability.severity,
            vuln_description=finding.vulnerability.description,
            vuln_status=finding.vulnerability.status,
            asset_name=finding.asset.name,
            asset_environment=finding.asset.environment,
            asset_type=finding.asset.type,
            asset_internet_facing=finding.asset.internet_facing,
        ).single()

    return {"created": dict(record)}


@app.get("/findings")
def list_findings():
    """Return every repository -> vulnerability -> asset chain in the graph."""
    query = """
    MATCH (repo:Repository)-[:CONTAINS]->(vuln:Vulnerability)-[:AFFECTS]->(asset:Asset)
    RETURN repo { .* } AS repository, vuln { .* } AS vulnerability, asset { .* } AS asset
    ORDER BY vuln.severity DESC
    """
    db = get_driver()
    with db.session() as session:
        results = session.run(query)
        return [
            {
                "repository": record["repository"],
                "vulnerability": record["vulnerability"],
                "asset": record["asset"],
            }
            for record in results
        ]


@app.get("/findings/{finding_id}")
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

    return {
        "vulnerability": record["vulnerability"],
        "repositories": record["repositories"],
        "assets": record["assets"],
    }


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@app.get("/assets")
def list_assets():
    query = """
    MATCH (asset:Asset)
    OPTIONAL MATCH (vuln:Vulnerability)-[:AFFECTS]->(asset)
    WHERE vuln.status = 'open'
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
            }
            for record in session.run(query)
        ]


@app.get("/graph")
def get_graph():
    query = """
    MATCH (n)
    WHERE n:Repository OR n:Vulnerability OR n:Asset
    OPTIONAL MATCH (n)-[r:CONTAINS|AFFECTS]->(m)
    RETURN n, labels(n)[0] AS label, type(r) AS rel, m, labels(m)[0] AS target_label
    """
    key_for = {"Repository": "name", "Vulnerability": "id", "Asset": "name"}

    def node_id(label: str, props: dict) -> str:
        return f"{label}:{props[key_for[label]]}"

    nodes: dict[str, dict] = {}
    links: list[dict] = []
    db = get_driver()
    with db.session() as session:
        for record in session.run(query):
            props = dict(record["n"])
            source = node_id(record["label"], props)
            nodes.setdefault(source, {"id": source, "label": record["label"], "properties": props})
            if record["rel"] is not None:
                target = node_id(record["target_label"], dict(record["m"]))
                links.append({"source": source, "target": target, "type": record["rel"]})

    return {"nodes": list(nodes.values()), "links": links}


def _trivy_description(vuln: TrivyVulnerability, target: str) -> str:
    title = vuln.Title or vuln.Description or vuln.VulnerabilityID
    fix = f"fixed in {vuln.FixedVersion}" if vuln.FixedVersion else "no fix available"
    return f"{title} ({vuln.PkgName} {vuln.InstalledVersion}, {fix}; {target})"


@app.post("/ingest/trivy", status_code=201)
def ingest_trivy(report: TrivyReport, params: Annotated[TrivyIngestParams, Query()]):
    repository = RepositoryIn(
        name=params.repo_name, url=params.repo_url, language=params.repo_language
    )
    asset = AssetIn(
        name=params.asset_name,
        environment=params.asset_environment,
        type=params.asset_type,
        internet_facing=params.asset_internet_facing,
    )

    findings: dict[str, FindingIngest] = {}
    skipped = 0
    for result in report.Results or []:
        for vuln in result.Vulnerabilities or []:
            if vuln.Severity not in SEVERITIES:
                skipped += 1
                continue
            finding = FindingIngest(
                repository=repository,
                vulnerability=VulnerabilityIn(
                    id=f"{repository.name}:{vuln.PkgName}:{vuln.VulnerabilityID}",
                    cve=vuln.VulnerabilityID if vuln.VulnerabilityID.upper().startswith("CVE-") else None,
                    severity=vuln.Severity,
                    description=_trivy_description(vuln, result.Target),
                ),
                asset=asset,
            )
            findings[finding.vulnerability.id] = finding

    for finding in findings.values():
        ingest_finding(finding)

    return {"ingested": len(findings), "skipped": skipped, "ids": list(findings)}
