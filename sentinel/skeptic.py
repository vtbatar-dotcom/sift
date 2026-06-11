"""Skeptic agent — wraps Claude API for adversarial finding review."""

from __future__ import annotations

import json
import os
from pathlib import Path

import anthropic

from .models import Citation, Finding, SkepticVerdict

PROMPT_PATH = Path(__file__).parent / "prompts" / "skeptic.md"
DEFAULT_MODEL = "claude-sonnet-4-20250514"


class SkepticAgent:
    def __init__(self, case_id: str, model: str | None = None):
        self.case_id = case_id
        self.model = model or os.environ.get("SENTINEL_SKEPTIC_MODEL", DEFAULT_MODEL)
        self.client = anthropic.Anthropic()
        self.system_prompt = PROMPT_PATH.read_text()

    async def review(self, finding: Finding, iteration: int = 0) -> SkepticVerdict:
        """Review a finding and return a verdict."""
        finding_json = finding.model_dump_json(indent=2)

        message = f"""Review this forensic finding and verify its citations independently.

Finding to review:
```json
Current iteration: {iteration}

Verify each citation. Render your verdict as JSON."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=self.system_prompt,
            messages=[{"role": "user", "content": message}],
        )

        text = response.content[0].text
        data = self._parse_json(text)
        data["finding_id"] = finding.finding_id
        data["iteration"] = iteration

        # Parse missing_citations into Citation objects
        missing = []
        for mc in data.get("missing_citations", []):
            if isinstance(mc, dict):
                missing.append(Citation(**mc))
        data["missing_citations"] = missing

        return SkepticVerdict(**data)

    @staticmethod
    def _parse_json(text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)
        return json.loads(text)
