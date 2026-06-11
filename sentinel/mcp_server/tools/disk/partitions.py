"""list_partitions — wraps mmls to enumerate partition table entries."""

from __future__ import annotations

import re
import subprocess
import time

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import safe_subprocess_args, validate_evidence_path


def list_partitions(image_path: str, case_id: str, session_hashes: dict[str, str]) -> ToolResult:
    """Run mmls against an E01 image and return structured partition data."""
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    argv = safe_subprocess_args("mmls", ["-i", "ewf", str(validated)])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)

    if result.returncode != 0:
        raise RuntimeError(f"mmls failed: {result.stderr.strip()}")

    rows = []
    citations = []

    for line in result.stdout.splitlines():
        match = re.match(
            r"(\d+):\s+"
            r"(\S+)\s+"
            r"(\d+)\s+"
            r"(\d+)\s+"
            r"(\d+)\s+"
            r"(.+)$",
            line.strip()
        )
        if not match:
            continue

        idx, slot, start, end, length, desc = match.groups()
        row = {
            "index": int(idx),
            "slot": slot,
            "start_sector": int(start),
            "end_sector": int(end),
            "length_sectors": int(length),
            "length_bytes": int(length) * 512,
            "description": desc.strip(),
        }
        rows.append(row)
        citations.append(Citation(
            artifact=str(validated),
            locator_type="byte_offset",
            locator=f"sector:{start}",
            excerpt=f"{desc.strip()} (sectors {start}-{end})",
        ))

    import hashlib, json
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="list_partitions",
        case_id=case_id,
        args={"image_path": image_path},
        source_artifact=str(validated),
        artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
        rows=rows,
        citations=citations,
        execution_time_ms=int((time.time_ns() - start_ns) / 1_000_000),
        output_hash=output_hash,
    )
