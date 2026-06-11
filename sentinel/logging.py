"""Structured JSONL logger for SIFT Sentinel."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


class ExecutionLogger:
    """Append-only JSONL logger for a single investigation session."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._entry_count = 0

    def _write(self, entry: dict[str, Any]) -> str:
        entry_id = str(uuid.uuid4())
        entry["entry_id"] = entry_id
        entry["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        entry["sequence"] = self._entry_count
        self._entry_count += 1
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return entry_id

    def log_tool_call(self, tool_name: str, args: dict, source_artifact: str,
                      output_hash: str, row_count: int, truncated: bool,
                      execution_time_ms: int) -> str:
        return self._write({
            "event": "tool_call", "tool_name": tool_name, "args": args,
            "source_artifact": source_artifact, "output_hash": output_hash,
            "row_count": row_count, "truncated": truncated,
            "execution_time_ms": execution_time_ms,
        })

    def log_analyst_draft(self, finding_id: str, finding_data: dict, iteration: int) -> str:
        return self._write({
            "event": "analyst_draft", "finding_id": finding_id,
            "iteration": iteration, "finding": finding_data,
        })

    def log_skeptic_verdict(self, finding_id: str, verdict: Literal["accepted", "rejected"],
                            reasons: list[str], iteration: int) -> str:
        return self._write({
            "event": "skeptic_verdict", "finding_id": finding_id,
            "verdict": verdict, "reasons": reasons, "iteration": iteration,
        })

    def log_session_event(self, event_type: str, details: dict | None = None) -> str:
        return self._write({"event": f"session_{event_type}", "details": details or {}})

    def compute_log_hash(self) -> str:
        if not self.log_path.exists():
            return hashlib.sha256(b"").hexdigest()
        h = hashlib.sha256()
        with open(self.log_path, "rb") as f:
            while True:
                chunk = f.read(8 * 1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()


class IterationTracer:
    """Per-finding JSONL trace for Skeptic-Analyst iterations."""

    def __init__(self, iterations_dir: Path):
        self.iterations_dir = iterations_dir
        self.iterations_dir.mkdir(parents=True, exist_ok=True)

    def _trace_path(self, finding_id: str) -> Path:
        return self.iterations_dir / f"{finding_id}.jsonl"

    def _append(self, finding_id: str, entry: dict) -> None:
        entry["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        with open(self._trace_path(finding_id), "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def trace_analyst_draft(self, finding_id: str, finding_data: dict, iteration: int) -> None:
        self._append(finding_id, {"phase": "analyst_draft", "iteration": iteration, "finding": finding_data})

    def trace_skeptic_verdict(self, finding_id: str, verdict: str, reasons: list[str], iteration: int) -> None:
        self._append(finding_id, {"phase": "skeptic_verdict", "iteration": iteration, "verdict": verdict, "reasons": reasons})

    def trace_analyst_revision(self, finding_id: str, finding_data: dict, iteration: int) -> None:
        self._append(finding_id, {"phase": "analyst_revision", "iteration": iteration, "finding": finding_data})

    def trace_final(self, finding_id: str, verdict: str) -> None:
        self._append(finding_id, {"phase": "final", "verdict": verdict})
