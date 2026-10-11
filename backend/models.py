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

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return _normalize_key(v).lower()


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



class TrivyIngestParams(BaseModel):
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


FindingStatus = Literal["open", "in_progress", "resolved", "accepted_risk", "false_positive"]
STATUSES: tuple[str, ...] = FindingStatus.__args__
ACTIVE_STATUSES = ["open", "in_progress"]


class StatusUpdate(BaseModel):
    status: FindingStatus


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
