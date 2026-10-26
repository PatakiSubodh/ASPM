from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def _normalize_key(value: str) -> str:
    value = " ".join(value.split())
    if not value:
        raise ValueError("must not be blank")
    return value


class RepositoryIn(BaseModel):
    name: str
    url: Optional[str] = None
    language: Optional[str] = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class VulnerabilityIn(BaseModel):
    id: str
    cve: Optional[str] = None
    severity: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    description: str

    @field_validator("id")
    @classmethod
    def normalize_id(cls, v: str) -> str:
        return _normalize_key(v).upper()


class AssetIn(BaseModel):
    name: str
    environment: str
    type: str
    internet_facing: bool = False
    image: Optional[str] = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class AssetUpdate(BaseModel):
    environment: Optional[str] = None
    type: Optional[str] = None
    internet_facing: Optional[bool] = None
    image: Optional[str] = None

    @model_validator(mode="after")
    def check_fields(self) -> "AssetUpdate":
        if not self.model_fields_set:
            raise ValueError("no fields to update")
        for field in ("environment", "type", "internet_facing"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} must not be null")
        return self


class RepositoryCreate(BaseModel):
    name: str
    url: str
    language: Optional[str] = None
    branch: Optional[str] = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()

    @field_validator("url")
    @classmethod
    def check_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("https://", "http://")):
            raise ValueError("url must start with https:// or http://")
        return v


class RepositoryUpdate(BaseModel):
    selected: Optional[bool] = None
    branch: Optional[str] = None

    @model_validator(mode="after")
    def check_fields(self) -> "RepositoryUpdate":
        if not self.model_fields_set:
            raise ValueError("no fields to update")
        if "selected" in self.model_fields_set and self.selected is None:
            raise ValueError("selected must not be null")
        if self.branch is not None:
            self.branch = _normalize_key(self.branch)
        return self


class RepositoryAssetsIn(BaseModel):
    assets: list[str] = []

    @field_validator("assets")
    @classmethod
    def normalize_assets(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(_normalize_key(name).lower() for name in v))


class FindingIngest(BaseModel):
    repository: RepositoryIn
    vulnerability: VulnerabilityIn
    asset: Optional[AssetIn] = None


class CatalogRepository(BaseModel):
    name: str
    url: str
    language: Optional[str] = None
    branch: Optional[str] = None
    assets: list[AssetIn] = []

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class CatalogIn(BaseModel):
    repositories: list[CatalogRepository] = []

    @model_validator(mode="after")
    def unique_repositories(self) -> "CatalogIn":
        names = [r.name for r in self.repositories]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate repositories: {', '.join(duplicates)}")
        return self


class DiscoveredAsset(BaseModel):
    name: str
    image: Optional[str] = None
    labels: dict[str, str] = {}

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()

    @field_validator("labels")
    @classmethod
    def require_aspm_labels(cls, v: dict[str, str]) -> dict[str, str]:
        if not v.get("aspm.environment", "").strip():
            raise ValueError("aspm.environment label is required")
        if v.get("aspm.internet_facing", "false").strip().lower() not in ("true", "false"):
            raise ValueError("aspm.internet_facing label must be 'true' or 'false'")
        return v


class DiscoveryIn(BaseModel):
    source: Literal["docker"] = "docker"
    assets: list[DiscoveredAsset] = []

    @model_validator(mode="after")
    def unique_assets(self) -> "DiscoveryIn":
        names = [a.name for a in self.assets]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate assets: {', '.join(duplicates)}")
        return self


class IngestParams(BaseModel):
    repo_name: str
    repo_url: Optional[str] = None
    repo_language: Optional[str] = None
    asset_name: Optional[str] = None
    asset_environment: Optional[str] = None
    asset_type: Optional[str] = None
    asset_internet_facing: bool = False
    commit: Optional[str] = None
    partial: bool = False

    @field_validator("repo_name", "asset_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class TrivyIngestParams(IngestParams):
    mode: Literal["fs", "image"] = "fs"


FindingStatus = Literal["open", "in_progress", "resolved", "accepted_risk", "false_positive"]
STATUSES: tuple[str, ...] = FindingStatus.__args__
ACTIVE_STATUSES = ["open", "in_progress"]


class StatusUpdate(BaseModel):
    status: FindingStatus


class GitHubLinkIn(BaseModel):
    code: str = Field(min_length=1, max_length=512)
    state: str = Field(min_length=1, max_length=2048)
    nonce: str = Field(min_length=1, max_length=256)


class GitHubRepositoryIn(BaseModel):
    full_name: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=200)


class ScanRunIn(BaseModel):
    repository: str
    scanners: list[Literal["trivy", "semgrep"]] = Field(
        default_factory=lambda: ["trivy", "semgrep"], min_length=1
    )

    @field_validator("repository")
    @classmethod
    def normalize_repository(cls, v: str) -> str:
        return _normalize_key(v).lower()

    @field_validator("scanners")
    @classmethod
    def dedupe_scanners(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


class JobCompleteIn(BaseModel):
    claim_id: str = Field(min_length=1, max_length=64)
    status: Literal["done", "failed"]
    scan_ids: list[str] = Field(default_factory=list, max_length=20)
    error: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def check_error(self) -> "JobCompleteIn":
        if self.status == "failed" and not (self.error or "").strip():
            raise ValueError("error is required when status is failed")
        return self


class ScanFailureIn(BaseModel):
    repo_name: str
    repo_url: Optional[str] = None
    scanner: str = Field(pattern="^[a-z0-9_-]+$")
    commit: Optional[str] = None
    error: str = Field(min_length=1, max_length=200)
    detail: Optional[str] = Field(default=None, max_length=500)

    @field_validator("repo_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


class NormalizedFinding(BaseModel):
    id: str
    cve: Optional[str] = None
    severity: str
    description: str
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    location: Optional[str] = None
    cwe: Optional[list[str]] = None
