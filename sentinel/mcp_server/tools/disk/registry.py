"""query_registry — extract and parse registry hives with regipy."""

from __future__ import annotations

import hashlib
import json
import time

from regipy.registry import RegistryHive

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import validate_evidence_path
from .extract import extract_hive


def query_registry(
    image_path: str,
    hive: str,
    key_path: str,
    case_id: str,
    session_hashes: dict[str, str],
    recursive: bool = False,
) -> ToolResult:
    """Read a registry key and its values from an offline hive."""
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    # Extract hive to cache
    hive_path = extract_hive(image_path, hive)

    # Parse with regipy
    reg = RegistryHive(str(hive_path))

    rows = []
    citations = []

    # regipy expects leading backslash
    if not key_path.startswith("\\"):
        key_path = "\\" + key_path

    try:
        key = reg.get_key(key_path)
    except Exception as e:
        # Key not found — return empty result (not an error)
        elapsed = int((time.time_ns() - start_ns) / 1_000_000)
        output_hash = hashlib.sha256(json.dumps([], default=str).encode()).hexdigest()
        return ToolResult(
            tool_name="query_registry",
            case_id=case_id,
            args={"image_path": image_path, "hive": hive, "key_path": key_path, "recursive": recursive},
            source_artifact=str(validated),
            artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
            rows=[],
            citations=[],
            execution_time_ms=elapsed,
            output_hash=output_hash,
        )

    # Process the key itself
    _add_key_data(key, key_path, hive, rows, citations, str(validated))

    # Process subkeys if recursive
    if recursive:
        _walk_subkeys(reg, key, key_path, hive, rows, citations, str(validated), depth=0, max_depth=3)

    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="query_registry",
        case_id=case_id,
        args={"image_path": image_path, "hive": hive, "key_path": key_path, "recursive": recursive},
        source_artifact=str(validated),
        artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
        rows=rows,
        citations=citations,
        execution_time_ms=elapsed,
        output_hash=output_hash,
    )


def _add_key_data(key, key_path, hive, rows, citations, artifact):
    """Extract values from a single registry key."""
    timestamp = str(key.header.last_modified) if hasattr(key.header, 'last_modified') else None

    if hasattr(key, 'get_values') and callable(key.get_values):
        for value in key.get_values():
            name = value.name if hasattr(value, 'name') else "(Default)"
            val_data = value.value if hasattr(value, 'value') else None
            val_type = value.value_type if hasattr(value, 'value_type') else "unknown"

            # Truncate large binary values for display
            display_data = val_data
            if isinstance(val_data, bytes) and len(val_data) > 256:
                display_data = val_data[:256].hex() + "...(truncated)"
            elif isinstance(val_data, bytes):
                display_data = val_data.hex()

            row = {
                "key_path": key_path,
                "value_name": name,
                "value_data": str(display_data),
                "value_type": str(val_type),
                "last_modified": timestamp,
            }
            rows.append(row)
            citations.append(Citation(
                artifact=artifact,
                locator_type="registry_key",
                locator=f"{hive}\\{key_path}\\{name}",
                excerpt=str(display_data)[:100] if display_data else None,
            ))

    # If no values, still record the key exists
    if not rows or rows[-1].get("key_path") != key_path:
        row = {
            "key_path": key_path,
            "value_name": "(key only)",
            "value_data": None,
            "value_type": None,
            "last_modified": timestamp,
        }
        rows.append(row)
        citations.append(Citation(
            artifact=artifact,
            locator_type="registry_key",
            locator=f"{hive}\\{key_path}",
        ))


def _walk_subkeys(reg, key, parent_path, hive, rows, citations, artifact, depth, max_depth):
    """Recursively walk subkeys up to max_depth."""
    if depth >= max_depth:
        return

    for subkey in key.iter_subkeys():
        sub_path = f"{parent_path}\\{subkey.name}"
        _add_key_data(subkey, sub_path, hive, rows, citations, artifact)
        _walk_subkeys(reg, subkey, sub_path, hive, rows, citations, artifact, depth + 1, max_depth)
