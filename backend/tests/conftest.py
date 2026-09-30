import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

os.environ.setdefault("ASPM_API_KEY", "pytest-key")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main
from fastapi.testclient import TestClient
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable


@pytest.fixture(scope="session")
def client():
    probe = GraphDatabase.driver(main.NEO4J_URI, auth=(main.NEO4J_USER, main.NEO4J_PASSWORD))
    try:
        probe.verify_connectivity()
    except (ServiceUnavailable, OSError):
        pytest.skip(f"Neo4j not reachable at {main.NEO4J_URI}")
    finally:
        probe.close()
    with TestClient(main.app, headers={"X-API-Key": main.ASPM_API_KEY}) as c:
        yield c


@pytest.fixture
def repo(client):
    name = f"pytest-{uuid4().hex[:10]}"
    yield name
    with main.get_driver().session() as session:
        session.run(
            """
            MATCH (r:Repository {name: $repo})
            OPTIONAL MATCH (r)-[:CONTAINS]->(v:Vulnerability)
            OPTIONAL MATCH (s:Scan)-[:SCANNED]->(r)
            OPTIONAL MATCH (a:Asset {name: $asset})
            WITH collect(DISTINCT r) + collect(DISTINCT v) + collect(DISTINCT s) + collect(DISTINCT a) AS nodes
            UNWIND nodes AS n
            DETACH DELETE n
            """,
            repo=name,
            asset=f"{name}-api",
        ).consume()
