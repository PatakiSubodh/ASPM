# Demo data

Everything fake lives here. Nothing in `backend/` or `frontend/` creates sample data, and a plain `docker compose up` starts with an empty graph.

| File | What it is |
|---|---|
| `seed.cypher` | Demo dataset. Every node has `demo: true`. Idempotent (`MERGE` on natural keys), timestamps relative to load time. |
| `purge.cypher` | Removes every `demo: true` node, plus anything ingested from `trivy-sample.json` as described below. Real data is untouched. |
| `trivy-sample.json` | A real `trivy fs --scanners vuln --format json` report of a small `requirements.txt` (jinja2, requests, pyyaml, urllib3). |

## What the seed covers

- 4 repositories (`acme-*`), 5 assets across production, staging and development, internet-facing and internal.
- 11 findings: all four severities, P1 to P4, every status (`open`, `in_progress`, `resolved`, `accepted_risk`, `false_positive`), SCA and SAST types.
- `DEPLOYS_TO` edges (`source: 'demo'`) for the `/catalog` page; `POST /catalog` and the startup catalog load never prune them.
- `acme-reports` has no deployed asset, so its Log4Shell finding is unmapped.
- `acme-staging-gateway` is shared by `acme-payments` and `acme-storefront`.
- 6 scan runs with ingested / resolved / reopened counts.

Keep `seed.cypher` in sync with the graph model: a model change and its seed change go in the same commit.

## Load

Stack and demo data together:

```bash
docker compose --profile demo up -d
```

Into an already running stack:

```bash
docker compose run --rm demo-seed
```

## Try the Trivy connector

```bash
curl -X POST "http://localhost:8000/ingest/trivy?repo_name=acme-sample&repo_url=https://git.example.com/acme/acme-sample&asset_name=acme-sample-api&asset_environment=staging&asset_type=Docker%20container&asset_internet_facing=true" \
  -H "X-API-Key: $ASPM_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @demo/trivy-sample.json
```

Use exactly `acme-sample` / `acme-sample-api` so `purge.cypher` removes the result. Posting the same file again shows dedup (`reopened: 0`, `resolved: 0`). Posting a report with some vulnerabilities removed auto-resolves them.

## Purge

```bash
docker exec -i aspm-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" < demo/purge.cypher
```

Check: `MATCH (n {demo: true}) RETURN count(n)` returns `0`.
