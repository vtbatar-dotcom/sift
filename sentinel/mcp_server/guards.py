"""Security guards for the SIFT Sentinel MCP server.

These are ARCHITECTURAL safety controls, not prompt-based restrictions.
"""

from __future__ import annotations

import os
from pathlib import Path

EVIDENCE_ROOT = Path("/evidence")
CACHE_DIR = Path("/var/cache/sentinel")
MAX_ROWS = 10_000
MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # 2 MiB

ALLOWED_BINARIES: dict[str, str] = {
    "fls": "/usr/bin/fls",
    "icat": "/usr/bin/icat",
    "istat": "/usr/bin/istat",
    "mmls": "/usr/bin/mmls",
    "mactime": "/usr/bin/mactime",
    "evtx_dump": "/usr/bin/evtx_dump",
    "analyzeMFT": "/usr/local/bin/analyzeMFT",
    "vol3": "/usr/local/bin/vol",
}


class PathGuardError(Exception):
    """Raised when a path escapes the evidence vault."""


def validate_evidence_path(path: str | Path) -> Path:
    resolved = Path(os.path.realpath(str(path)))
    if not resolved.is_relative_to(EVIDENCE_ROOT):
        raise PathGuardError(
            f"Path '{path}' resolves to '{resolved}', which is outside "
            f"the evidence vault ({EVIDENCE_ROOT}). Access denied."
        )
    if not resolved.exists():
        raise PathGuardError(f"Path '{resolved}' does not exist inside the evidence vault.")
    return resolved


def validate_cache_path(path: str | Path) -> Path:
    resolved = Path(os.path.realpath(str(path)))
    if resolved.is_relative_to(EVIDENCE_ROOT):
        raise PathGuardError(
            f"Attempted to use evidence vault path '{resolved}' as a cache location. "
            f"Cache writes must go to {CACHE_DIR}."
        )
    return resolved


class OutputTruncated(Exception):
    """Raised when output exceeds configured limits."""


def bound_rows(rows: list[dict], max_rows: int = MAX_ROWS) -> tuple[list[dict], bool]:
    if len(rows) <= max_rows:
        return rows, False
    return rows[:max_rows], True


def check_output_size(data: bytes, max_bytes: int = MAX_OUTPUT_BYTES) -> None:
    if len(data) > max_bytes:
        raise OutputTruncated(
            f"Output size ({len(data):,} bytes) exceeds limit ({max_bytes:,} bytes)."
        )


class ShellInjectionError(Exception):
    """Raised if an agent-controlled string reaches a shell context."""


def safe_subprocess_args(binary_key: str, args: list[str]) -> list[str]:
    if binary_key not in ALLOWED_BINARIES:
        raise ShellInjectionError(
            f"Binary '{binary_key}' is not in the allowed list. "
            f"Available: {sorted(ALLOWED_BINARIES.keys())}"
        )
    binary_path = ALLOWED_BINARIES[binary_key]
    SHELL_METACHARS = set(";|&`$(){}[]!#~<>\\'\"\n\r")
    for arg in args:
        dangerous = SHELL_METACHARS.intersection(arg)
        if dangerous:
            raise ShellInjectionError(
                f"Argument contains shell metacharacter(s) {dangerous}: '{arg}'."
            )
    return [binary_path] + args


def open_evidence_readonly(path: str | Path):
    validated = validate_evidence_path(path)
    return open(validated, "rb")
