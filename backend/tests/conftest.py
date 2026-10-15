import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

os.environ.setdefault("ASPM_API_KEY", "pytest-key")
os.environ.setdefault("SUPABASE_URL", "https://pytest.supabase.co")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auth
import db
import main
from fastapi.testclient import TestClient
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())
TEST_USER_ID = "pytest-user"


class StaticJWKS:
    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=SIGNING_KEY.public_key())


def make_token(**overrides) -> str:
    now = int(time.time())
    claims = {
        "sub": TEST_USER_ID,
        "email": "pytest@example.com",
        "aud": "authenticated",
        "iss": "https://pytest.supabase.co/auth/v1",
        "iat": now,
        "exp": now + 3600,
        "app_metadata": {"provider": "email"},
        "user_metadata": {},
    }
    claims.update(overrides)
    return jwt.encode(claims, SIGNING_KEY, algorithm="ES256")


@pytest.fixture(scope="session")
def client():
    probe = GraphDatabase.driver(db.NEO4J_URI, auth=(db.NEO4J_USER, db.NEO4J_PASSWORD))
    try:
        probe.verify_connectivity()
    except (ServiceUnavailable, OSError):
        pytest.skip(f"Neo4j not reachable at {db.NEO4J_URI}")
    finally:
        probe.close()
    with TestClient(main.app, headers={"X-API-Key": main.ASPM_API_KEY}) as c:
        auth.jwks_client = StaticJWKS()
        c.headers["Authorization"] = f"Bearer {make_token()}"
        yield c
        with main.get_driver().session() as session:
            session.run("MATCH (u:User {id: $id}) DETACH DELETE u", id=TEST_USER_ID).consume()


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
            OPTIONAL MATCH (a:Asset) WHERE a.name STARTS WITH $repo
            WITH collect(DISTINCT r) + collect(DISTINCT v) + collect(DISTINCT s) + collect(DISTINCT a) AS nodes
            UNWIND nodes AS n
            DETACH DELETE n
            """,
            repo=name,
        ).consume()
