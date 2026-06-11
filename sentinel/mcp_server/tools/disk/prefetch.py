"""parse_prefetch — extract and parse Windows Prefetch files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import safe_subprocess_args, validate_evidence_path, bound_rows

CACHE_DIR = "/var/cache/sentinel"
PREFETCH_DIR_MFT = "10203"  # M57-Jean specific; will be auto-discovered later


def parse_prefetch(
    image_path: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    """Extract and parse all Prefetch files from the disk image."""
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    # Step 1: List all .pf files
    fls_argv = safe_subprocess_args("fls", ["-i", "ewf", "-o", "63", str(validated), PREFETCH_DIR_MFT])
    fls_result = subprocess.run(fls_argv, capture_output=True, text=True, timeout=60)

    if fls_result.returncode != 0:
        raise RuntimeError(f"fls failed: {fls_result.stderr.strip()}")

    pf_files = []
    for line in fls_result.stdout.splitlines():
        match = re.match(r"r/r\s+(\S+):\s+(.+\.pf)$", line.strip(), re.IGNORECASE)
        if match:
            pf_files.append((match.group(1), match.group(2)))

    # Step 2: Extract and parse each
    rows = []
    citations = []

    pf_cache = os.path.join(CACHE_DIR, "prefetch")
    os.makedirs(pf_cache, exist_ok=True)

    for mft_entry, filename in pf_files:
        out_path = os.path.join(pf_cache, filename)
        icat_argv = safe_subprocess_args(
            "icat", ["-i", "ewf", "-o", "63", str(validated), mft_entry]
        )

        with open(out_path, "wb") as f:
            icat_result = subprocess.run(icat_argv, stdout=f, stderr=subprocess.PIPE, timeout=30)

        if icat_result.returncode != 0 or not os.path.exists(out_path):
            continue

        if os.path.getsize(out_path) == 0:
            continue

        # Parse the prefetch file
        try:
            pf_data = _parse_pf(out_path)
        except Exception:
            continue

        if pf_data:
            pf_data["mft_entry"] = mft_entry
            pf_data["filename"] = filename
            rows.append(pf_data)
            citations.append(Citation(
                artifact=str(validated),
                locator_type="mft_entry",
                locator=mft_entry,
                excerpt=f"{pf_data.get('executable', filename)} run {pf_data.get('run_count', '?')} time(s)",
            ))

    # Sort by last run time descending
    rows.sort(key=lambda r: r.get("last_run_time", ""), reverse=True)
    rows, truncated = bound_rows(rows)

    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="parse_prefetch",
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


def _parse_pf(path: str) -> dict | None:
    """Parse a Windows Prefetch file. Handles XP (v17) format directly."""
    import struct
    import datetime

    try:
        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 100:
            return None

        version = struct.unpack_from("<I", data, 0)[0]

        # Exe name: offset 16, 60 bytes, UTF-16LE
        exe_name = data[16:76].decode("utf-16-le", errors="ignore").split("\x00")[0]

        if version == 17:
            # XP format
            run_count = struct.unpack_from("<I", data, 144)[0]
            filetime = struct.unpack_from("<Q", data, 120)[0]
        elif version == 23:
            # Vista/Win7
            run_count = struct.unpack_from("<I", data, 152)[0]
            filetime = struct.unpack_from("<Q", data, 128)[0]
        else:
            run_count = None
            filetime = 0

        # FILETIME to ISO string
        epoch_diff = 116444736000000000
        if filetime > epoch_diff:
            ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
            last_run = ts.strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_run = "unknown"

        return {
            "executable": exe_name,
            "run_count": run_count,
            "last_run_time": last_run,
            "prefetch_hash": path.split("-")[-1].replace(".pf", ""),
        }
    except Exception:
        return None
