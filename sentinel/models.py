"""Core data models for SIFT Sentinel.

Every finding MUST carry at least one Citation. This is enforced by Pydantic
validation -- not by prompts. If the Analyst produces a finding without a
citation, it fails schema validation before the Skeptic ever sees it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Citation(BaseModel):
    """A pointer to a specific location inside a forensic artifact."""

    artifact: str = Field(
        ...,
        description="Path to the evidence file inside the vault",
    )
    locator_type: Literal[
        "byte_offset", "mft_entry", "registry_key",
        "evt_record", "pid", "vaddr", "file_path",
    ] = Field(..., description="What kind of pointer this is")
    locator: str = Field(
        ...,
        description="The actual pointer value",
    )
    excerpt: str | None = Field(default=None)


class TimelineEntry(BaseModel):
    """A single event in a finding's reconstructed timeline."""

    timestamp_utc: datetime
    source: str = Field(..., description="Provenance: mft | amcache | evtx | prefetch | shimcache | ...")
    description: str
    citation_index: int = Field(..., description="Index into the parent Finding's evidence[] list")


class ToolResult(BaseModel):
    """Standardized return type for every MCP tool."""

    tool_name: str
    case_id: str
    args: dict
    source_artifact: str
    artifact_hash_at_session_start: str
    rows: list[dict]
    citations: list[Citation]
    truncated: bool = False
    continuation_cursor: str | None = None
    execution_time_ms: int
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    output_hash: str = Field(..., description="SHA-256 of the JSON-serialized rows")


class Finding(BaseModel):
    """A single investigative finding.

    Schema validation enforces that evidence[] is non-empty. A finding
    literally cannot exist without at least one citation.
    """

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    title: str
    severity: Literal["info", "low", "med", "high", "critical"]
    narrative: str = Field(
        ..., description="1-3 paragraphs. Must reference citations by index.",
    )
    claim_type: Literal["confirmed", "inferred"]
    mitre_attack: list[str] = Field(default_factory=list)
    evidence: list[Citation] = Field(..., min_length=1)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    supersedes: list[str] = Field(default_factory=list)
    iteration: int = Field(default=0)
    analyst_model: str = Field(default="claude-opus-4-7")
    skeptic_verdict: Literal["accepted", "rejected", "unverified"] = "unverified"
    tool_calls: list[str] = Field(default_factory=list)

    @field_validator("evidence")
    @classmethod
    def evidence_must_not_be_empty(cls, v: list[Citation]) -> list[Citation]:
        if len(v) == 0:
            raise ValueError("A finding MUST have at least one citation.")
        return v


class SkepticVerdict(BaseModel):
    """What the Skeptic returns after reviewing a Finding."""

    finding_id: str
    verdict: Literal["accepted", "rejected"]
    reasons: list[str] = Field(default_factory=list)
    missing_citations: list[Citation] = Field(default_factory=list)
    re_verified_tool_calls: list[str] = Field(default_factory=list)
    iteration: int


class EvidenceFile(BaseModel):
    """One entry in the evidence manifest."""

    path: str
    sha256: str
    file_type: Literal["disk_image", "memory_dump", "supplemental"]
    size_bytes: int


class CaseManifest(BaseModel):
    """Top-level manifest for a case's evidence files."""

    case_id: str
    description: str = ""
    evidence_files: list[EvidenceFile]
    created_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SessionRecord(BaseModel):
    """Tracks a single investigation session's integrity."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    started_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_utc: datetime | None = None
    start_hashes: dict[str, str] = Field(default_factory=dict)
    end_hashes: dict[str, str] = Field(default_factory=dict)
    hash_mismatches: list[str] = Field(default_factory=list)
    findings_accepted: int = 0
    findings_rejected: int = 0
    total_iterations: int = 0
    status: Literal["active", "completed", "integrity_violation"] = "active"
