"""list_run_keys — enumerate autorun persistence from registry Run/RunOnce keys."""

from __future__ import annotations

import hashlib
import json
import time

from regipy.registry import RegistryHive

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import validate_evidence_path, bound_rows
from .extract import extract_hive

# All the standard autorun locations
RUN_KEY_PATHS = {
    "SOFTWARE": [
        "\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    ],
}

NTUSER_RUN_PATHS = [
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]

# MFT entries for NTUSER.DAT files (M57-Jean specific)
NTUSER_MFT = {
    "Jean": "10226-128-4",
    "Devon": "7503-128-3",
}


def list_run_keys(
    image_path: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    """List all autorun persistence entries from Run/RunOnce keys."""
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    rows = []
    citations = []

    # Machine-level keys from SOFTWARE hive
    sw_path = extract_hive(image_path, 'SOFTWARE')
    sw_reg = RegistryHive(str(sw_path))

    for key_path in RUN_KEY_PATHS["SOFTWARE"]:
        try:
            key = sw_reg.get_key(key_path)
            for val in key.get_values():
                rows.append({
                    "scope": "machine",
                    "hive": "SOFTWARE",
                    "key_path": key_path,
                    "name": val.name,
                    "value": str(val.value),
                })
                citations.append(Citation(
                    artifact=str(validated),
                    locator_type="registry_key",
                    locator=f"SOFTWARE{key_path}\\{val.name}",
                    excerpt=str(val.value)[:100],
                ))
        except Exception:
            continue

    # Per-user keys from NTUSER.DAT
    for user, mft_entry in NTUSER_MFT.items():
        try:
            from .extract import extract_file
            ntuser_path = extract_file(image_path, mft_entry, f"hive_NTUSER_{user}")
            ntuser_reg = RegistryHive(str(ntuser_path))

            for key_path in NTUSER_RUN_PATHS:
                try:
                    key = ntuser_reg.get_key(key_path)
                    for val in key.get_values():
                        rows.append({
                            "scope": f"user:{user}",
                            "hive": f"NTUSER.DAT ({user})",
                            "key_path": key_path,
                            "name": val.name,
                            "value": str(val.value),
                        })
                        citations.append(Citation(
                            artifact=str(validated),
                            locator_type="registry_key",
                            locator=f"NTUSER({user}){key_path}\\{val.name}",
                            excerpt=str(val.value)[:100],
                        ))
                except Exception:
                    continue
        except Exception:
            continue

    rows, truncated = bound_rows(rows)
    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="list_run_keys",
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
