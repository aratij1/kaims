from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CorpusClassification(StrEnum):
    PRODUCTION_CURATED = "PRODUCTION_CURATED"
    TENANT_CURATED = "TENANT_CURATED"
    GENERATED_UNVERIFIED = "GENERATED_UNVERIFIED"
    DEMO_ONLY = "DEMO_ONLY"
    MALFORMED = "MALFORMED"
    OBSOLETE = "OBSOLETE"


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class RagGovernanceMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=3, max_length=160)
    tenant_scope: str = Field(min_length=1, max_length=128)
    services: list[str] = Field(default_factory=list)
    owner_team: str = Field(min_length=1, max_length=160)
    source_system: str = Field(min_length=1, max_length=160)
    source_ref: str = Field(min_length=1, max_length=500)
    review_status: ReviewStatus
    corpus_classification: CorpusClassification
    content_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    last_reviewed: datetime | None = None
    reviewed_by: str | None = Field(default=None, max_length=160)
    approved_by: str | None = Field(default=None, max_length=160)
    approved_at: datetime | None = None
    content_checksum: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("services")
    @classmethod
    def normalize_services(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(item.strip().lower() for item in value if item.strip()))


def utc_now() -> datetime:
    return datetime.now(UTC)


def content_checksum(content: str) -> str:
    normalized = str(content or "").replace("\r\n", "\n").strip() + "\n"
    return f"sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"


def retrieval_allowed(metadata: RagGovernanceMetadata | dict[str, Any], tenant_id: str) -> bool:
    try:
        governed = (
            metadata
            if isinstance(metadata, RagGovernanceMetadata)
            else RagGovernanceMetadata.model_validate(metadata_from_headers(metadata))
        )
    except (TypeError, ValueError):
        return False
    tenant = str(tenant_id or "").strip()
    if not tenant or governed.review_status is not ReviewStatus.APPROVED:
        return False
    if governed.tenant_scope == tenant:
        return governed.corpus_classification is CorpusClassification.TENANT_CURATED
    return (
        governed.tenant_scope.lower() == "global"
        and governed.corpus_classification is CorpusClassification.PRODUCTION_CURATED
    )


def production_retrievable(metadata: RagGovernanceMetadata | dict[str, Any]) -> bool:
    try:
        governed = (
            metadata
            if isinstance(metadata, RagGovernanceMetadata)
            else RagGovernanceMetadata.model_validate(metadata_from_headers(metadata))
        )
    except (TypeError, ValueError):
        return False
    if governed.review_status is not ReviewStatus.APPROVED:
        return False
    if governed.tenant_scope.lower() == "global":
        return governed.corpus_classification is CorpusClassification.PRODUCTION_CURATED
    return governed.corpus_classification is CorpusClassification.TENANT_CURATED


def approval_classification(*, tenant_scope: str, global_approval: bool) -> CorpusClassification:
    if str(tenant_scope).strip().lower() == "global":
        if not global_approval:
            raise ValueError("global production approval requires explicit administrator authorization")
        return CorpusClassification.PRODUCTION_CURATED
    return CorpusClassification.TENANT_CURATED


def metadata_from_headers(metadata: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(metadata)
    services = normalized.get("services", [])
    if isinstance(services, str):
        normalized["services"] = [item.strip() for item in services.split(",") if item.strip()]
    if "content_version" in normalized:
        try:
            normalized["content_version"] = int(normalized["content_version"])
        except (TypeError, ValueError):
            pass
    return normalized


def validate_governed_metadata(metadata: dict[str, Any]) -> RagGovernanceMetadata | None:
    try:
        return RagGovernanceMetadata.model_validate(metadata_from_headers(metadata))
    except (TypeError, ValueError):
        return None
