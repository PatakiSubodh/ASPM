from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException

from db import get_driver
from models import AssetIn, RepositoryIn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


ASSET_UPSERT_QUERY = """
MERGE (asset:Asset {name: $asset.name})
  ON CREATE SET
    asset.environment = $asset.environment,
    asset.type = $asset.type,
    asset.internet_facing = $asset.internet_facing,
    asset.image = $asset.image
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
    vuln.cwe = f.cwe,
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
  WHERE $link_deployed
  MERGE (vuln)-[affects:AFFECTS]->(deployed)
    ON CREATE SET affects.source = 'catalog'
}
RETURN count(vuln) AS ingested, sum(CASE WHEN reopened THEN 1 ELSE 0 END) AS reopened
"""

AUTO_RESOLVE_QUERY = """
MATCH (:Repository {name: $repo})-[:CONTAINS]->(v:Vulnerability {scanner: $scanner})
WHERE v.status IN ['open', 'in_progress'] AND v.last_scan_id <> $scan_id
  AND ($asset IS NULL OR EXISTS { (v)-[:AFFECTS]->(:Asset {name: $asset}) })
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
    link_deployed: bool = True,
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
        link_deployed=link_deployed,
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
    image: bool = False,
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
        counts = ingest_batch(
            tx, repo, asset, scanner, scan_id, findings, started_at, type, not image
        )
        resolved = 0
        if not partial:
            resolved = tx.run(
                AUTO_RESOLVE_QUERY,
                repo=repo.name,
                scanner=scanner,
                scan_id=scan_id,
                now=started_at,
                asset=asset.name if image and asset else None,
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
