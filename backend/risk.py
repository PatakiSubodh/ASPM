from typing import Optional


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
ENVIRONMENT_WEIGHT = {
    "production": 1.0,
    "prod": 1.0,
    "staging": 0.6,
    "stage": 0.6,
    "uat": 0.6,
    "qa": 0.6,
    "development": 0.3,
    "dev": 0.3,
    "test": 0.3,
}
DEFAULT_ENVIRONMENT_WEIGHT = 0.6
INTERNET_FACING_WEIGHT = 1.5
MAX_RISK = SEVERITY_WEIGHT["CRITICAL"] * ENVIRONMENT_WEIGHT["production"] * INTERNET_FACING_WEIGHT
PRIORITY_BANDS = ((70, "P1"), (40, "P2"), (20, "P3"), (0, "P4"))


def risk_score(severity: str, environment: Optional[str], internet_facing: bool) -> dict:
    severity_weight = SEVERITY_WEIGHT.get(severity, SEVERITY_WEIGHT["LOW"])
    environment_weight = ENVIRONMENT_WEIGHT.get(
        (environment or "").strip().lower(), DEFAULT_ENVIRONMENT_WEIGHT
    )
    exposure_weight = INTERNET_FACING_WEIGHT if internet_facing else 1.0
    score = min(100, round(severity_weight * environment_weight * exposure_weight / MAX_RISK * 100))
    priority = next(p for threshold, p in PRIORITY_BANDS if score >= threshold)
    return {
        "score": score,
        "priority": priority,
        "factors": {
            "severity": severity_weight,
            "environment": environment_weight,
            "exposure": exposure_weight,
        },
    }


def asset_risk(severity: str, asset: dict) -> dict:
    return risk_score(severity, asset.get("environment"), bool(asset.get("internet_facing")))
