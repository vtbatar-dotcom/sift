"""get_mft_timeline — generate filtered MFT timeline via fls + mactime."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import subprocess
import time
from datetime import datetime

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import (
    safe_subprocess_args,
    validate_evidence_path,
    bound_rows,
)

CACHE_DIR = "/var/cache/sentinel"


def get_mft_timeline(
    image_path: str,
    start_utc: str,
    end_utc: str,
    case_id: str,
    session_hashes: dict[str, str],
    path_filter: str | None = None,
) -> ToolResult:
    """Extract MFT timeline entries within a UTC time range.

    Uses fls to generate a body file, then mactime to filter and format.
    """
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    # Step 1: fls -r -m / to generate body file
    fls_argv = safe_subprocess_args("fls", ["-r", "-m", "/", "-i", "ewf", "-o", "63", str(validated)])
    body_path = f"{CACHE_DIR}/bodyfile.txt"

    with open(body_path, "w") as bf:
        fls_result = subprocess.run(fls_argv, stdout=bf, stderr=subprocess.PIPE, timeout=300)

    if fls_result.returncode != 0:
        raise RuntimeError(f"fls failed: {fls_result.stderr.decode().strip()}")

    # Step 2: mactime to filter by date range
    # mactime expects dates as YYYY-MM-DD
    start_date = start_utc[:10]
    end_date = end_utc[:10]

    mactime_argv = safe_subprocess_args("mactime", ["-b", body_path, "-d", start_date, end_date])
    mac_result = subprocess.run(mactime_argv, capture_output=True, text=True, timeout=120)

    if mac_result.returncode != 0:
        raise RuntimeError(f"mactime failed: {mac_result.stderr.strip()}")

    # Step 3: Parse mactime CSV output
    rows = []
    citations = []

    reader = csv.reader(io.StringIO(mac_result.stdout))
    for line in reader:
        if len(line) < 4:
            continue

        # mactime -d output: Date,Size,Type,Mode,UID,GID,Meta,File Name
        if line[0].strip().lower().startswith("date"):
            continue  # skip header

        if len(line) >= 8:
            timestamp = line[0].strip()
            size = line[1].strip()
            activity_type = line[2].strip()
            mode = line[3].strip()
            uid = line[4].strip()
            gid = line[5].strip()
            meta = line[6].strip()
            file_name = line[7].strip()
        else:
            continue

        # Apply path filter if specified
        if path_filter and path_filter.lower() not in file_name.lower():
            continue

        row = {
            "timestamp": timestamp,
            "size": size,
            "activity_type": activity_type,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "meta": meta,
            "file_name": file_name,
        }
        rows.append(row)
        citations.append(Citation(
            artifact=str(validated),
            locator_type="mft_entry",
            locator=meta,
            excerpt=f"{activity_type} {file_name} at {timestamp}",
        ))

    # Bound output
    rows, truncated = bound_rows(rows)

    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="get_mft_timeline",
        case_id=case_id,
        args={
            "image_path": image_path, "start_utc": start_utc,
            "end_utc": end_utc, "path_filter": path_filter,
        },
        source_artifact=str(validated),
        artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
        rows=rows,
        citations=citations,
        truncated=truncated,
        execution_time_ms=elapsed,
        output_hash=output_hash,
    )
