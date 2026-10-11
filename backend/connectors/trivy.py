from typing import Optional

from pydantic import BaseModel

from models import NormalizedFinding, _normalize_key
from risk import SEVERITIES


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


def _trivy_description(vuln: TrivyVulnerability, target: str) -> str:
    title = vuln.Title or vuln.Description or vuln.VulnerabilityID
    fix = f"fixed in {vuln.FixedVersion}" if vuln.FixedVersion else "no fix available"
    return f"{title} ({vuln.PkgName} {vuln.InstalledVersion}, {fix}; {target})"


def parse(report: TrivyReport, repo_name: str) -> tuple[list[NormalizedFinding], int]:
    findings: dict[str, NormalizedFinding] = {}
    skipped = 0
    for result in report.Results or []:
        for vuln in result.Vulnerabilities or []:
            if vuln.Severity not in SEVERITIES:
                skipped += 1
                continue
            vuln_id = _normalize_key(f"{repo_name}:{vuln.PkgName}:{vuln.VulnerabilityID}").upper()
            findings[vuln_id] = NormalizedFinding(
                id=vuln_id,
                cve=vuln.VulnerabilityID if vuln.VulnerabilityID.upper().startswith("CVE-") else None,
                severity=vuln.Severity,
                description=_trivy_description(vuln, result.Target),
                package=vuln.PkgName,
                installed_version=vuln.InstalledVersion,
                fixed_version=vuln.FixedVersion,
                location=result.Target,
            )
    return list(findings.values()), skipped
