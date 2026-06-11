"""list_services — enumerate Windows services from the SYSTEM registry hive."""

from __future__ import annotations

import hashlib
import json
import time

from regipy.registry import RegistryHive

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import validate_evidence_path, bound_rows
from .extract import extract_hive


def list_services(
    image_path: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    """List Windows services from ControlSet001\\Services."""
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)
    hive_path = extract_hive(image_path, 'SYSTEM')

    reg = RegistryHive(str(hive_path))
    services_key = reg.get_key('\\ControlSet001\\Services')

    rows = []
    citations = []

    for svc in services_key.iter_subkeys():
        row = {
            "name": svc.name,
            "start_type": None,
            "type": None,
            "image_path": None,
            "display_name": None,
        }

        try:
            for val in svc.get_values():
                if val.name == "Start":
                    row["start_type"] = val.value
                elif val.name == "Type":
                    row["type"] = val.value
                elif val.name == "ImagePath":
                    row["image_path"] = str(val.value)
                elif val.name == "DisplayName":
                    row["display_name"] = str(val.value)
        except Exception:
            pass

        rows.append(row)
        citations.append(Citation(
            artifact=str(validated),
            locator_type="registry_key",
            locator=f"SYSTEM\\ControlSet001\\Services\\{svc.name}",
            excerpt=row.get("image_path"),
        ))

    rows, truncated = bound_rows(rows)
    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="list_services",
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
