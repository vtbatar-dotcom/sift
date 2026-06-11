"""Skeptic agent — wraps Claude API for adversarial finding review."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import anthropic

from .models import Citation, Finding, SkepticVerdict

PROMPT_PATH = Path(__file__).parent / "prompts" / "skeptic.md"
DEFAULT_MODEL = "claude-sonnet-4-6"


class SkepticAgent:
    def __init__(self, case_id: str, model: str | None = None):
        self.case_id = case_id
        self.model = model or os.environ.get("SENTINEL_SKEPTIC_MODEL", DEFAULT_MODEL)
        self.client = anthropic.Anthropic()
        self.system_prompt = PROMPT_PATH.read_text()

    async def review(self, finding: Finding, iteration: int = 0) -> SkepticVerdict:
        """Review a finding and return a verdict."""

        # Build a clear, flat representation of the finding
        evidence_text = ""
        for i, cit in enumerate(finding.evidence):
            evidence_text += f"\n  Citation [{i+1}]: {cit.locator_type} = {cit.locator} in {cit.artifact}"
            if cit.excerpt:
                evidence_text += f"\n    Excerpt: {cit.excerpt}"

        timeline_text = ""
        for te in finding.timeline:
            timeline_text += f"\n  - {te.timestamp_utc} ({te.source}): {te.description}"

        message = f"""FINDING TO REVIEW:

Title: {finding.title}
Severity: {finding.severity}
Claim Type: {finding.claim_type}
Finding ID: {finding.finding_id}

Narrative:
{finding.narrative}

Evidence:{evidence_text}

Timeline:{timeline_text if timeline_text else " (none provided)"}

MITRE ATT&CK: {', '.join(finding.mitre_attack) if finding.mitre_attack else 'none'}

Current iteration: {iteration}

INSTRUCTIONS: Verify each citation above. Then respond with ONLY this JSON (no other text):
{{"finding_id": "{finding.finding_id}", "verdict": "accepted" or "rejected", "reasons": ["reason1"], "missing_citations": [], "re_verified_tool_calls": [], "iteration": {iteration}}}"""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=self.system_prompt,
            messages=[{"role": "user", "content": message}],
        )

        text = response.content[0].text
        data = self._parse_json(text)

        data["finding_id"] = finding.finding_id
        data["iteration"] = iteration

        # Normalize verdict — anything not explicitly accepted is rejected
        v = str(data.get("verdict", "rejected")).lower().strip()
        if v in ("accepted", "accept", "approved", "pass", "valid", "confirmed"):
            v = "accepted"
        else:
            v = "rejected"
        data["verdict"] = v

        # Ensure reasons is a list of strings
        reasons = data.get("reasons", data.get("reason", data.get("rejection_reasons", [])))
        if isinstance(reasons, str):
            reasons = [reasons]
        elif not isinstance(reasons, list):
            reasons = []
        data["reasons"] = [str(r) for r in reasons]

        # Ensure missing_citations is a list
        mc_raw = data.get("missing_citations", [])
        missing = []
        if isinstance(mc_raw, list):
            for mc in mc_raw:
                if isinstance(mc, dict):
                    try:
                        missing.append(Citation(**mc))
                    except Exception:
                        pass
        data["missing_citations"] = missing

        # Clean extra fields
        valid_fields = {"finding_id", "verdict", "reasons", "missing_citations", "re_verified_tool_calls", "iteration"}
        data = {k: v for k, v in data.items() if k in valid_fields}
        if "re_verified_tool_calls" not in data:
            data["re_verified_tool_calls"] = []
        else:
            # Coerce to list of strings
            rvtc = data["re_verified_tool_calls"]
            if isinstance(rvtc, list):
                data["re_verified_tool_calls"] = [str(x) if not isinstance(x, str) else x for x in rvtc]
            else:
                data["re_verified_tool_calls"] = []

        return SkepticVerdict(**data)

    @staticmethod
    def _parse_json(text: str) -> dict:
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        if "```" in text:
            match = re.search(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        return {
            "verdict": "rejected",
            "reasons": ["Skeptic response was not valid JSON"],
            "missing_citations": [],
        }
