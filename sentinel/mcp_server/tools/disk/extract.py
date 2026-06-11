"""Extract files from E01 images via icat. Always to cache dir, never to evidence vault."""

from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.mcp_server.guards import safe_subprocess_args, validate_evidence_path

CACHE_DIR = Path("/var/cache/sentinel")

# Hive name -> MFT entry mapping (M57-Jean specific; will be auto-discovered later)
HIVE_MFT_ENTRIES = {
    "SAM": "3515-128-3",
    "SECURITY": "3514-128-3",
    "SOFTWARE": "3386-128-3",
    "SYSTEM": "1892-128-3",
    "DEFAULT": "4144-128-3",
}


def extract_file(image_path: str, mft_entry: str, output_name: str) -> Path:
    """Extract a file from an E01 image to the cache directory.

    Returns the path to the extracted file. Writes ONLY to CACHE_DIR.
    """
    validated = validate_evidence_path(image_path)
    out_path = CACHE_DIR / output_name

    argv = safe_subprocess_args("icat", ["-i", "ewf", "-o", "63", str(validated), mft_entry])
    with open(out_path, "wb") as f:
        result = subprocess.run(argv, stdout=f, stderr=subprocess.PIPE, timeout=120)

    if result.returncode != 0:
        raise RuntimeError(f"icat failed: {result.stderr.decode().strip()}")

    if not out_path.exists() or out_path.stat().st_size == 0:
        raise RuntimeError(f"Extraction produced empty file: {out_path}")

    return out_path


def extract_hive(image_path: str, hive_name: str) -> Path:
    """Extract a registry hive by name."""
    hive_upper = hive_name.upper()
    if hive_upper not in HIVE_MFT_ENTRIES:
        raise ValueError(f"Unknown hive '{hive_name}'. Available: {sorted(HIVE_MFT_ENTRIES.keys())}")

    mft_entry = HIVE_MFT_ENTRIES[hive_upper]
    return extract_file(image_path, mft_entry, f"hive_{hive_upper}")
