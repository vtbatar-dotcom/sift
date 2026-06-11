"""get_browser_history — extract and parse browser history databases."""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
import time

from sentinel.models import Citation, ToolResult
from sentinel.mcp_server.guards import validate_evidence_path, bound_rows
from .extract import extract_file

FIREFOX_MFT = {
    "Jean": "18075-128-4",
    "Devon": "11370-128-4",
}


def get_browser_history(
    image_path: str,
    user: str,
    browser: str,
    case_id: str,
    session_hashes: dict[str, str],
) -> ToolResult:
    start_ns = time.time_ns()
    validated = validate_evidence_path(image_path)

    rows = []
    citations = []

    if browser.lower() == "firefox":
        mft_entry = FIREFOX_MFT.get(user)
        if not mft_entry:
            raise ValueError(f"No Firefox profile known for user '{user}'.")
        db_path = extract_file(image_path, mft_entry, f"places_{user}.sqlite")
        rows, citations = _parse_firefox(str(db_path), str(validated))
    else:
        raise ValueError(f"Browser '{browser}' not supported. Available: firefox")

    rows, truncated = bound_rows(rows)
    elapsed = int((time.time_ns() - start_ns) / 1_000_000)
    output_hash = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()

    return ToolResult(
        tool_name="get_browser_history",
        case_id=case_id,
        args={"image_path": image_path, "user": user, "browser": browser},
        source_artifact=str(validated),
        artifact_hash_at_session_start=session_hashes.get(str(validated), "unknown"),
        rows=rows,
        citations=citations,
        truncated=truncated,
        execution_time_ms=elapsed,
        output_hash=output_hash,
    )


def _parse_firefox(db_path: str, artifact: str) -> tuple[list[dict], list[Citation]]:
    rows = []
    citations = []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.execute("""
            SELECT
                p.url,
                p.title,
                p.visit_count,
                v.visit_date,
                v.visit_type
            FROM moz_places p
            LEFT JOIN moz_historyvisits v ON p.id = v.place_id
            WHERE p.url NOT LIKE 'place:%'
            ORDER BY v.visit_date DESC
        """)

        for row in cursor:
            visit_ts = row['visit_date']
            visit_str = ""
            if visit_ts:
                try:
                    visit_str = datetime.datetime.fromtimestamp(
                        visit_ts / 1_000_000
                    ).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, OSError):
                    visit_str = str(visit_ts)

            entry = {
                "url": row['url'],
                "title": row['title'] or "",
                "visit_count": row['visit_count'],
                "visit_date": visit_str,
                "visit_type": row['visit_type'],
            }
            rows.append(entry)
            citations.append(Citation(
                artifact=artifact,
                locator_type="file_path",
                locator=f"Firefox/places.sqlite:moz_places:url={row['url'][:80]}",
                excerpt=f"{visit_str} {row['url'][:60]}",
            ))
    finally:
        conn.close()

    return rows, citations
