"""verify_image_hash — compare evidence hash against session manifest."""

from __future__ import annotations

import hashlib
import json
import time

from sentinel.models import Citation, ToolResult
from sentinel.evidence import sha256_file
from sentinel.mcp_server.guards import validate_evidence_path

def verify_image_hash(
    image_path: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)
    computed = sha256_file(validated)
    expected = session_hashes.get(str(validated), "")
    matches = computed == expected

    rows = [{
        "image_path": str(validated),
        "computed_sha256": computed,
        "manifest_sha256": expected,
        "matches": matches,
    }]

    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows).encode()).hexdigest()

    return ToolResult(
        tool_name="verify_image_hash",
        case_id=case_id,
        args={"image_path": image_path},
        source_artifact=str(validated),
        artifact_hash_at_session_start=expected,
        rows=rows,
        citations=[Citation(
            artifact=str(validated),
            locator_type="byte_offset",
            locator="0x0",
            excerpt=f"SHA-256: {computed[:32]}... matches={matches}",
        )],
        execution_time_ms=elapsed,
        output_hash=output_hash,
    )
