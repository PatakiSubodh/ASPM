"""
ASPM Backend — FastAPI service backed by Neo4j.

Graph model:
    (:Repository)-[:CONTAINS]->(:Vulnerability)-[:AFFECTS]->(:Asset)

This lets us answer the core ASPM question: "which production assets are
exposed by which vulnerable code, and where did that vulnerability come from?"
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase, Driver
from pydantic import BaseModel, Field

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

class RepositoryIn(BaseModel):
    name: str
    url: str
    language: Optional[str] = None


class VulnerabilityIn(BaseModel):
    id: str
    cve: Optional[str] = None
    severity: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    description: str
    status: str = "open"


class AssetIn(BaseModel):
    name: str
    environment: str
    type: str
    internet_facing: bool = False


class FindingIngest(BaseModel):
    repository: RepositoryIn
    vulnerability: VulnerabilityIn
    asset: AssetIn


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
