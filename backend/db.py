import os
from typing import Optional

from fastapi import HTTPException
from neo4j import Driver, GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "aspm_dev_password")

driver: Optional[Driver] = None


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
    "CREATE CONSTRAINT user_id_unique IF NOT EXISTS "
    "FOR (u:User) REQUIRE u.id IS UNIQUE",
]



def ensure_constraints(db: Driver) -> None:
    with db.session() as session:
        for statement in CONSTRAINTS:
            session.run(statement).consume()


def connect_driver() -> Driver:
    global driver
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    ensure_constraints(driver)
    return driver


def close_driver() -> None:
    if driver is not None:
        driver.close()
