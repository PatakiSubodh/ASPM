UNWIND [
  {name: 'acme-payments', url: 'https://git.example.com/acme/acme-payments', language: 'Python', scanned: 'PT2H'},
  {name: 'acme-storefront', url: 'https://git.example.com/acme/acme-storefront', language: 'TypeScript', scanned: 'PT5H'},
  {name: 'acme-auth', url: 'https://git.example.com/acme/acme-auth', language: 'Go', scanned: 'P1D'},
  {name: 'acme-reports', url: 'https://git.example.com/acme/acme-reports', language: 'Java', scanned: 'P3D'}
] AS r
MERGE (repo:Repository {name: r.name})
SET repo.url = r.url,
    repo.language = r.language,
    repo.last_scanned_at = toString(datetime() - duration(r.scanned)),
    repo.demo = true;

UNWIND [
  {name: 'acme-payments-api', environment: 'production', type: 'Kubernetes Service', internet_facing: true},
  {name: 'acme-storefront-web', environment: 'production', type: 'Kubernetes Service', internet_facing: true},
  {name: 'acme-auth-api', environment: 'production', type: 'Kubernetes Service', internet_facing: false},
  {name: 'acme-staging-gateway', environment: 'staging', type: 'Docker container', internet_facing: true},
  {name: 'acme-dev-sandbox', environment: 'development', type: 'Virtual machine', internet_facing: false}
] AS a
MERGE (asset:Asset {name: a.name})
SET asset.environment = a.environment,
    asset.type = a.type,
    asset.internet_facing = a.internet_facing,
    asset.demo = true;

UNWIND [
  {id: 'demo-scan-payments-1', repo: 'acme-payments', scanner: 'trivy', commit: '4e1c9a2', started: 'P7D', ingested: 3, resolved: 0, reopened: 0},
  {id: 'demo-scan-payments-2', repo: 'acme-payments', scanner: 'trivy', commit: '9b07d3f', started: 'PT2H', ingested: 2, resolved: 1, reopened: 0},
  {id: 'demo-scan-storefront-1', repo: 'acme-storefront', scanner: 'trivy', commit: 'c2f81e0', started: 'PT5H', ingested: 3, resolved: 0, reopened: 1},
  {id: 'demo-scan-storefront-2', repo: 'acme-storefront', scanner: 'semgrep', commit: 'c2f81e0', started: 'PT5H', ingested: 1, resolved: 0, reopened: 0},
  {id: 'demo-scan-auth-1', repo: 'acme-auth', scanner: 'trivy', commit: '71aa04d', started: 'P1D', ingested: 3, resolved: 0, reopened: 0},
  {id: 'demo-scan-reports-1', repo: 'acme-reports', scanner: 'trivy', commit: 'e5d2b19', started: 'P3D', ingested: 1, resolved: 0, reopened: 0}
] AS s
MATCH (repo:Repository {name: s.repo})
MERGE (scan:Scan {id: s.id})
SET scan.scanner = s.scanner,
    scan.commit = s.commit,
    scan.partial = false,
    scan.started_at = toString(datetime() - duration(s.started)),
    scan.finished_at = toString(datetime() - duration(s.started) + duration('PT48S')),
    scan.ingested = s.ingested,
    scan.resolved = s.resolved,
    scan.reopened = s.reopened,
    scan.skipped = 0,
    scan.demo = true
MERGE (scan)-[:SCANNED]->(repo);

UNWIND [
  {id: 'ACME-PAYMENTS:PYYAML:CVE-2020-14343', repo: 'acme-payments', assets: ['acme-payments-api', 'acme-staging-gateway'],
   cve: 'CVE-2020-14343', severity: 'CRITICAL', status: 'open', scanner: 'trivy', type: 'sca',
   package: 'pyyaml', installed_version: '5.3', fixed_version: '5.4', location: 'requirements.txt',
   description: 'PyYAML full_load allows arbitrary code execution when processing untrusted YAML (pyyaml 5.3, fixed in 5.4; requirements.txt)',
   first_seen: 'P7D', last_seen: 'PT2H', scan: 'demo-scan-payments-2'},
  {id: 'ACME-PAYMENTS:JINJA2:CVE-2024-22195', repo: 'acme-payments', assets: ['acme-payments-api'],
   cve: 'CVE-2024-22195', severity: 'MEDIUM', status: 'in_progress', scanner: 'trivy', type: 'sca',
   package: 'jinja2', installed_version: '3.1.2', fixed_version: '3.1.3', location: 'requirements.txt',
   description: 'Jinja2 xmlattr filter allows HTML attribute injection (jinja2 3.1.2, fixed in 3.1.3; requirements.txt)',
   first_seen: 'P7D', last_seen: 'PT2H', scan: 'demo-scan-payments-2', changed: 'P2D'},
  {id: 'ACME-PAYMENTS:REQUESTS:CVE-2023-32681', repo: 'acme-payments', assets: ['acme-payments-api'],
   cve: 'CVE-2023-32681', severity: 'MEDIUM', status: 'resolved', scanner: 'trivy', type: 'sca',
   package: 'requests', installed_version: '2.28.1', fixed_version: '2.31.0', location: 'requirements.txt',
   description: 'Requests leaks Proxy-Authorization headers to destination servers on redirect (requests 2.28.1, fixed in 2.31.0; requirements.txt)',
   first_seen: 'P7D', last_seen: 'P7D', scan: 'demo-scan-payments-1', resolved: 'PT2H'},
  {id: 'ACME-STOREFRONT:SEMGREP:3F9A1C2B7D10', repo: 'acme-storefront', assets: ['acme-storefront-web', 'acme-staging-gateway'],
   severity: 'HIGH', status: 'open', scanner: 'semgrep', type: 'sast', location: 'src/api/search.ts:42',
   description: 'User-controlled search term is concatenated into a raw SQL query (tainted-sql-string)',
   first_seen: 'PT5H', last_seen: 'PT5H', scan: 'demo-scan-storefront-2'},
  {id: 'ACME-STOREFRONT:AXIOS:CVE-2023-45857', repo: 'acme-storefront', assets: ['acme-storefront-web'],
   cve: 'CVE-2023-45857', severity: 'MEDIUM', status: 'accepted_risk', scanner: 'trivy', type: 'sca',
   package: 'axios', installed_version: '1.5.1', fixed_version: '1.6.0', location: 'package-lock.json',
   description: 'Axios exposes the XSRF-TOKEN cookie to third-party hosts (axios 1.5.1, fixed in 1.6.0; package-lock.json)',
   first_seen: 'P20D', last_seen: 'PT5H', scan: 'demo-scan-storefront-1', changed: 'P10D'},
  {id: 'ACME-STOREFRONT:SEMVER:CVE-2022-25883', repo: 'acme-storefront', assets: ['acme-staging-gateway'],
   cve: 'CVE-2022-25883', severity: 'MEDIUM', status: 'open', scanner: 'trivy', type: 'sca',
   package: 'semver', installed_version: '7.5.1', fixed_version: '7.5.2', location: 'package-lock.json',
   description: 'semver is vulnerable to regular expression denial of service via untrusted ranges (semver 7.5.1, fixed in 7.5.2; package-lock.json)',
   first_seen: 'P12D', last_seen: 'PT5H', scan: 'demo-scan-storefront-1', reopened: 'PT5H'},
  {id: 'ACME-STOREFRONT:COOKIE:CVE-2024-47764', repo: 'acme-storefront', assets: ['acme-storefront-web'],
   cve: 'CVE-2024-47764', severity: 'LOW', status: 'open', scanner: 'trivy', type: 'sca',
   package: 'cookie', installed_version: '0.6.0', fixed_version: '0.7.0', location: 'package-lock.json',
   description: 'cookie accepts out-of-bounds characters in name, path and domain (cookie 0.6.0, fixed in 0.7.0; package-lock.json)',
   first_seen: 'P12D', last_seen: 'PT5H', scan: 'demo-scan-storefront-1'},
  {id: 'ACME-AUTH:GOLANG.ORG/X/CRYPTO:CVE-2024-45337', repo: 'acme-auth', assets: ['acme-auth-api'],
   cve: 'CVE-2024-45337', severity: 'CRITICAL', status: 'open', scanner: 'trivy', type: 'sca',
   package: 'golang.org/x/crypto', installed_version: 'v0.21.0', fixed_version: 'v0.31.0', location: 'go.mod',
   description: 'Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass (golang.org/x/crypto v0.21.0, fixed in v0.31.0; go.mod)',
   first_seen: 'P1D', last_seen: 'P1D', scan: 'demo-scan-auth-1'},
  {id: 'ACME-AUTH:GITHUB.COM/GOLANG-JWT/JWT/V4:CVE-2024-51744', repo: 'acme-auth', assets: ['acme-auth-api'],
   cve: 'CVE-2024-51744', severity: 'LOW', status: 'false_positive', scanner: 'trivy', type: 'sca',
   package: 'github.com/golang-jwt/jwt/v4', installed_version: 'v4.5.0', fixed_version: 'v4.5.1', location: 'go.mod',
   description: 'Bad documentation of error handling in ParseWithClaims can lead to accepting invalid tokens (jwt v4.5.0, fixed in v4.5.1; go.mod)',
   first_seen: 'P1D', last_seen: 'P1D', scan: 'demo-scan-auth-1', changed: 'PT20H'},
  {id: 'ACME-AUTH:GOLANG.ORG/X/NET:CVE-2023-44487', repo: 'acme-auth', assets: ['acme-dev-sandbox'],
   cve: 'CVE-2023-44487', severity: 'HIGH', status: 'open', scanner: 'trivy', type: 'sca',
   package: 'golang.org/x/net', installed_version: 'v0.15.0', fixed_version: 'v0.17.0', location: 'go.mod',
   description: 'HTTP/2 rapid reset can cause denial of service (golang.org/x/net v0.15.0, fixed in v0.17.0; go.mod)',
   first_seen: 'P1D', last_seen: 'P1D', scan: 'demo-scan-auth-1'},
  {id: 'ACME-REPORTS:ORG.APACHE.LOGGING.LOG4J:LOG4J-CORE:CVE-2021-44228', repo: 'acme-reports', assets: [],
   cve: 'CVE-2021-44228', severity: 'CRITICAL', status: 'open', scanner: 'trivy', type: 'sca',
   package: 'org.apache.logging.log4j:log4j-core', installed_version: '2.14.1', fixed_version: '2.15.0', location: 'pom.xml',
   description: 'Log4Shell: JNDI lookups in log messages allow remote code execution (log4j-core 2.14.1, fixed in 2.15.0; pom.xml)',
   first_seen: 'P3D', last_seen: 'P3D', scan: 'demo-scan-reports-1'}
] AS v
MATCH (repo:Repository {name: v.repo})
MERGE (vuln:Vulnerability {id: v.id})
SET vuln.cve = v.cve,
    vuln.severity = v.severity,
    vuln.description = v.description,
    vuln.status = v.status,
    vuln.scanner = v.scanner,
    vuln.type = v.type,
    vuln.package = v.package,
    vuln.installed_version = v.installed_version,
    vuln.fixed_version = v.fixed_version,
    vuln.location = v.location,
    vuln.first_seen = toString(datetime() - duration(v.first_seen)),
    vuln.last_seen = toString(datetime() - duration(v.last_seen)),
    vuln.last_scan_id = v.scan,
    vuln.resolved_at = CASE WHEN v.resolved IS NULL THEN null ELSE toString(datetime() - duration(v.resolved)) END,
    vuln.reopened_at = CASE WHEN v.reopened IS NULL THEN null ELSE toString(datetime() - duration(v.reopened)) END,
    vuln.status_changed_at = CASE WHEN v.changed IS NULL THEN null ELSE toString(datetime() - duration(v.changed)) END,
    vuln.demo = true
MERGE (repo)-[:CONTAINS]->(vuln)
WITH vuln, v
UNWIND v.assets AS asset_name
MATCH (asset:Asset {name: asset_name})
MERGE (vuln)-[:AFFECTS]->(asset);
