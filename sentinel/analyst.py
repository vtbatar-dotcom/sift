"""Analyst agent — wraps Claude API for forensic analysis."""

from __future__ import annotations

import json
import re
import os
from pathlib import Path

import anthropic

from .models import Finding, SkepticVerdict

PROMPT_PATH = Path(__file__).parent / "prompts" / "analyst.md"
DEFAULT_MODEL = "claude-sonnet-4-6"


class AnalystAgent:
    def __init__(self, case_id: str, image_path: str, model: str | None = None):
        self.case_id = case_id
        self.image_path = image_path
        self.model = model or os.environ.get("SENTINEL_ANALYST_MODEL", DEFAULT_MODEL)
        self.client = anthropic.Anthropic()
        self.system_prompt = PROMPT_PATH.read_text()
        self.conversation: list[dict] = []

    def _call(self, user_message: str) -> str:
        """Make a single API call and return the text response."""
        self.conversation.append({"role": "user", "content": user_message})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=8192,
            system=self.system_prompt,
            messages=self.conversation,
        )

        text = response.content[0].text
        self.conversation.append({"role": "assistant", "content": text})
        return text

    async def analyze(self, prompt: str, tool_results: dict | None = None) -> list[dict]:
        """Run the initial analysis. Returns raw finding dicts."""
        message = f"""Case ID: {self.case_id}
Evidence: {self.image_path}

Investigation prompt: {prompt}

"""
        if tool_results:
            message += "Here are the tool results gathered so far:\n\n"
            for tool_name, result in tool_results.items():
                message += f"### {tool_name}\n```json\n{json.dumps(result, indent=2, default=str)[:3000]}\n```\n\n"

        message += "\nProduce your findings as a JSON array."

        text = self._call(message)
        return self._parse_findings(text)

    async def revise(self, finding: Finding, verdict: SkepticVerdict) -> Finding:
        """Revise a finding based on Skeptic feedback."""
        message = f"""The Skeptic REJECTED your finding "{finding.title}".

Reasons for rejection:
{json.dumps(verdict.reasons, indent=2)}

Missing citations:
{json.dumps([c.model_dump() for c in verdict.missing_citations], indent=2)}

Please revise this finding to address all rejection reasons. Either:
1. Add the missing citations with real evidence
2. Remove unsupported claims
3. Downgrade claim_type from "confirmed" to "inferred" if evidence is circumstantial

Return the revised finding as a single JSON object (not an array).
Use these EXACT field names: title, severity (info/low/med/high/critical), narrative (string), claim_type (confirmed/inferred), evidence (list), timeline (list), mitre_attack (list)."""

        text = self._call(message)
        try:
            data = self._parse_json(text)
        except Exception:
            # If we can't parse, return the original finding
            return finding
        if isinstance(data, list):
            data = data[0] if data else {}
        data["case_id"] = self.case_id
        data["finding_id"] = finding.finding_id
        data["supersedes"] = [finding.finding_id]

        # Use the same normalization as initial findings
        from .investigator import normalize_finding
        data = normalize_finding(data, self.case_id)
        data["finding_id"] = finding.finding_id
        data["supersedes"] = [finding.finding_id]

        try:
            return Finding(**data)
        except Exception:
            return finding

    def _parse_findings(self, text: str) -> list[dict]:
        """Extract JSON findings from LLM response."""
        data = self._parse_json(text)
        if isinstance(data, dict):
            data = [data]
        for d in data:
            d["case_id"] = self.case_id
        return data

    @staticmethod
    def _parse_json(text: str) -> dict | list:
        """Parse JSON from text, handling markdown fences and preamble."""
        text = text.strip()
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Strip markdown fences
        if "```" in text:
            match = re.search(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass
        # Find first [ ... ] or { ... } block
        for pattern in [r"(\[.*\])", r"(\{.*\})"]:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
        raise ValueError(f"Could not parse JSON from response: {text[:200]}")
