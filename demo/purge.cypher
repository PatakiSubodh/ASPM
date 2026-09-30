MATCH (n {demo: true}) DETACH DELETE n;

MATCH (repo:Repository {name: 'acme-sample'})
OPTIONAL MATCH (repo)-[:CONTAINS]->(vuln:Vulnerability)
OPTIONAL MATCH (scan:Scan)-[:SCANNED]->(repo)
WITH collect(DISTINCT repo) + collect(DISTINCT vuln) + collect(DISTINCT scan) AS nodes
UNWIND nodes AS n
DETACH DELETE n;

MATCH (asset:Asset {name: 'acme-sample-api'}) DETACH DELETE asset;
