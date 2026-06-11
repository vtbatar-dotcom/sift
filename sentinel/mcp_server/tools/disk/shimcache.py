"""parse_shimcache — extract AppCompatCache for program execution evidence."""

from __future__ import annotations

import hashlib
import json
import time

from regipy.registry import RegistryHive

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import validate_evidence_path, bound_rows
from .extract import extract_hive


def parse_shimcache(
    image_path: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    """Parse ShimCache from SYSTEM hive for program execution evidence."""
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)
    hive_path = extract_hive(image_path, 'SYSTEM')

    reg = RegistryHive(str(hive_path))

    rows = []
    citations = []

    try:
        from regipy.plugins.system.shimcache import ShimCachePlugin
        plugin = ShimCachePlugin(reg, as_json=True)
        plugin.run()

        for entry in plugin.entries:
            row = {}
            for item in entry.get('values', []):
                if isinstance(item, dict):
                    row.update(item)
                else:
                    row['raw'] = str(item)
            if row:
                rows.append(row)
                p = row.get('path', row.get('Path', 'unknown'))
                citations.append(Citation(
                    artifact=str(validated),
                    locator_type="registry_key",
                    locator="SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                    excerpt=str(p)[:100],
                ))
    except Exception:
        # XP uses a different AppCompat format not supported by regipy plugin
        pass

    rows, truncated = bound_rows(rows)
    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="parse_shimcache",
        case_id=case_id,
        args={"image_path": image_path},
        source_artifact=str(validated),
        artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
        rows=rows,
        citations=citations,
        truncated=truncated,
        execution_time_ms=elapsed,
        output_hash=output_hash,
    )
