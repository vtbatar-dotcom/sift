"""list_user_profiles — enumerate user profiles from the registry."""

from __future__ import annotations

import hashlib
import json
import time

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import validate_evidence_path
from .registry import query_registry

def list_user_profiles(
    image_path: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    r = query_registry(
        image_path, 'SOFTWARE',
        'Microsoft\\Windows NT\\CurrentVersion\\ProfileList',
        case_id, session_hashes, recursive=True
    )

    profiles = {}
    for row in r.rows:
        key_parts = row['key_path'].split('\\')
        sid = key_parts[-1] if key_parts else ''
        if not sid.startswith('S-1-5-'):
            continue
        if sid not in profiles:
            profiles[sid] = {'sid': sid}
        if row['value_name'] == 'ProfileImagePath':
            profiles[sid]['profile_path'] = row['value_data']
        elif row['value_name'] == 'Flags':
            profiles[sid]['flags'] = row['value_data']

    rows = list(profiles.values())
    citations = [
        Citation(
            artifact=str(validated),
            locator_type="registry_key",
            locator=f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{p['sid']}",
            excerpt=p.get('profile_path', ''),
        )
        for p in rows
    ]

    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="list_user_profiles",
        case_id=case_id,
        args={"image_path": image_path},
        source_artifact=str(validated),
        artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
        rows=rows,
        citations=citations,
        execution_time_ms=elapsed,
        output_hash=output_hash,
    )
