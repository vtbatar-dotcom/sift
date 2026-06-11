"""Coordinator -- the deterministic loop driving the Skeptic-Analyst interaction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .logging import ExecutionLogger, IterationTracer
from .models import Finding, SkepticVerdict

DEFAULT_MAX_ITERATIONS = 5


class Coordinator:
    def __init__(self, case_id: str, session_dir: Path,
                 max_iterations: int = DEFAULT_MAX_ITERATIONS,
                 analyst: Any = None, skeptic: Any = None):
        self.case_id = case_id
        self.max_iterations = max_iterations
        self.analyst = analyst
        self.skeptic = skeptic
        self.execution_log = ExecutionLogger(session_dir / "execution.jsonl")
        self.iteration_tracer = IterationTracer(session_dir.parent / "iterations")
        self.accepted_findings: list[Finding] = []
        self.rejected_findings: list[Finding] = []

    async def investigate(self, prompt: str) -> "InvestigationResult":
        self.execution_log.log_session_event("investigation_start", {"prompt": prompt})
        raw_findings = await self._run_analyst(prompt)
        validated = self._validate_findings(raw_findings)
        for finding in validated:
            final = await self._skeptic_loop(finding)
            if final.skeptic_verdict == "accepted":
                self.accepted_findings.append(final)
            else:
                self.rejected_findings.append(final)
        self.execution_log.log_session_event("investigation_end", {
            "accepted": len(self.accepted_findings),
            "rejected": len(self.rejected_findings),
        })
        return InvestigationResult(
            case_id=self.case_id, accepted=self.accepted_findings,
            unverified=self.rejected_findings,
            log_hash=self.execution_log.compute_log_hash(),
        )

    async def _run_analyst(self, prompt: str) -> list[dict]:
        if self.analyst is None:
            raise NotImplementedError("Analyst agent not yet connected (Phase 4).")
        return await self.analyst.analyze(prompt)

    def _validate_findings(self, raw_findings: list[dict]) -> list[Finding]:
        validated = []
        for i, raw in enumerate(raw_findings):
            try:
                validated.append(Finding(**raw))
            except ValidationError as e:
                self.execution_log.log_session_event("schema_validation_failure", {
                    "finding_index": i, "errors": e.errors(), "raw_data": raw,
                })
        return validated

    async def _skeptic_loop(self, finding: Finding) -> Finding:
        current = finding
        for iteration in range(self.max_iterations):
            current.iteration = iteration
            self.iteration_tracer.trace_analyst_draft(
                current.finding_id, current.model_dump(mode="json"), iteration)
            self.execution_log.log_analyst_draft(
                current.finding_id, current.model_dump(mode="json"), iteration)
            verdict = await self._run_skeptic(current)
            self.iteration_tracer.trace_skeptic_verdict(
                current.finding_id, verdict.verdict, verdict.reasons, iteration)
            self.execution_log.log_skeptic_verdict(
                current.finding_id, verdict.verdict, verdict.reasons, iteration)
            if verdict.verdict == "accepted":
                current.skeptic_verdict = "accepted"
                self.iteration_tracer.trace_final(current.finding_id, "accepted")
                return current
            if iteration < self.max_iterations - 1:
                current = await self._run_analyst_revision(current, verdict)
                self.iteration_tracer.trace_analyst_revision(
                    current.finding_id, current.model_dump(mode="json"), iteration + 1)
        current.skeptic_verdict = "rejected"
        self.iteration_tracer.trace_final(current.finding_id, "rejected")
        return current

    async def _run_skeptic(self, finding: Finding) -> SkepticVerdict:
        if self.skeptic is None:
            raise NotImplementedError("Skeptic agent not yet connected (Phase 4).")
        return await self.skeptic.review(finding)

    async def _run_analyst_revision(self, finding: Finding, verdict: SkepticVerdict) -> Finding:
        if self.analyst is None:
            raise NotImplementedError("Analyst agent not yet connected.")
        return await self.analyst.revise(finding, verdict)


class InvestigationResult:
    def __init__(self, case_id: str, accepted: list[Finding],
                 unverified: list[Finding], log_hash: str):
        self.case_id = case_id
        self.accepted = accepted
        self.unverified = unverified
        self.log_hash = log_hash

    def summary(self) -> str:
        return "\n".join([
            f"Investigation complete for case {self.case_id}",
            f"  Accepted findings: {len(self.accepted)}",
            f"  Unverified hypotheses: {len(self.unverified)}",
            f"  Execution log hash: {self.log_hash[:16]}...",
        ])

    def to_json(self) -> str:
        return json.dumps({
            "case_id": self.case_id,
            "accepted_findings": [f.model_dump(mode="json") for f in self.accepted],
            "unverified_hypotheses": [f.model_dump(mode="json") for f in self.unverified],
            "log_hash": self.log_hash,
        }, indent=2, default=str)
