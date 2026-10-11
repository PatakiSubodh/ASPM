import hashlib
from typing import Any, Optional

from pydantic import BaseModel

from models import NormalizedFinding, _normalize_key
from risk import SEVERITIES

SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
UNAVAILABLE_LINES = "requires login"


class SemgrepPosition(BaseModel):
    line: int = 0


class SemgrepExtra(BaseModel):
    message: Optional[str] = None
    severity: str = ""
    lines: Optional[str] = None
    metadata: dict[str, Any] = {}


class SemgrepResult(BaseModel):
    check_id: str
    path: str
    start: SemgrepPosition = SemgrepPosition()
    extra: SemgrepExtra = SemgrepExtra()


class SemgrepReport(BaseModel):
    results: Optional[list[SemgrepResult]] = None


def _severity(value: str) -> Optional[str]:
    value = value.strip().upper()
    value = SEVERITY_MAP.get(value, value)
    return value if value in SEVERITIES else None


def _cwe(metadata: dict[str, Any]) -> Optional[list[str]]:
    raw = metadata.get("cwe")
    if not raw:
        return None
    items = raw if isinstance(raw, list) else [raw]
    return [str(item) for item in items]


def _code(extra: SemgrepExtra) -> str:
    if not extra.lines or extra.lines.strip().lower() == UNAVAILABLE_LINES:
        return ""
    return " ".join(extra.lines.split())


def parse(report: SemgrepReport, repo_name: str) -> tuple[list[NormalizedFinding], int]:
    findings: dict[str, NormalizedFinding] = {}
    seen: dict[str, int] = {}
    skipped = 0
    for result in sorted(report.results or [], key=lambda r: (r.path, r.start.line)):
        severity = _severity(result.extra.severity)
        if severity is None:
            skipped += 1
            continue
        digest = hashlib.sha1(
            f"{result.check_id}\n{result.path}\n{_code(result.extra)}".encode("utf-8")
        ).hexdigest()[:12]
        occurrence = seen.get(digest, 0)
        seen[digest] = occurrence + 1
        if occurrence:
            digest = hashlib.sha1(f"{digest}\n{occurrence}".encode("utf-8")).hexdigest()[:12]
        vuln_id = _normalize_key(f"{repo_name}:SEMGREP:{digest}").upper()
        findings[vuln_id] = NormalizedFinding(
            id=vuln_id,
            severity=severity,
            description=result.extra.message or result.check_id,
            location=f"{result.path}:{result.start.line}",
            cwe=_cwe(result.extra.metadata),
        )
    return list(findings.values()), skipped
