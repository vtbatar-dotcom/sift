# SIFT Sentinel — Project Overview

## What It Is

SIFT Sentinel is a digital forensics investigation tool that uses two AI agents to analyze disk images while preventing hallucination and evidence tampering. It wraps the SIFT Workstation's forensic tools in a read-only MCP server and orchestrates a dual-agent loop where every finding must be backed by verifiable evidence citations.

## The Problem

Current AI-assisted forensic tools suffer from two weaknesses:

1. **Hallucination** — AI agents fabricate evidence or make claims not supported by actual artifact data
2. **Prompt-only safety** — safety guardrails exist only in system prompts, which can be bypassed

## The Solution

SIFT Sentinel addresses both through architectural enforcement:

- **Structural citation validation:** Every finding must carry at least one citation pointing to a real artifact location (MFT entry, registry key, file path). This is enforced by Pydantic schema validation, not prompts. A finding literally cannot exist without evidence.

- **Skeptic-Analyst dual-agent loop:** The Analyst examines evidence and produces findings. The Skeptic independently reviews each finding, checking that citations point to real data and that claims follow from evidence. Rejected findings go back to the Analyst for revision. This loop runs up to 5 iterations before marking a finding as unverified.

- **Architectural safety:** The MCP server exposes only read-only tools. No shell, write, or delete capability exists in the tool surface. Evidence is mounted read-only at the OS level. Hash verification at session start and end confirms no modification occurred.

## Demonstrated Results

In the first end-to-end investigation of the M57-Jean disk image:

- The Analyst produced 10 findings from 8 forensic tools
- The Skeptic reviewed all findings, accepting 7 and rejecting 2
- **Self-correction demonstrated:** The Skeptic caught timestamp mismatches, CONFIRMED/INFERRED conflation, incorrect MITRE ATT&CK mappings, and unsupported claims. The Analyst successfully revised and corrected these issues.
- Evidence integrity was verified — zero hash mismatches at session end
- Zero spoliation events — the system cannot modify evidence by design

## Key Findings from M57-Jean Investigation

1. Machine identified as JEAN-13FBF038A3 running Windows XP in VMware
2. Three user accounts: Jean, Devon, Administrator
3. Suspicious executable HELPER.EXE executed 3 times (flagged high severity)
4. Firefox browser history showing travel planning (Google Maps, Travelocity)
5. WUAUCLT.EXE with anomalously high run count (757 executions)
6. No malicious persistence beyond VMware Tools in registry Run keys

## Architecture
## Tech Stack

- Python 3.11+, Anthropic Claude API, MCP Python SDK
- Sleuth Kit (fls, icat, mmls, mactime), regipy, SQLite
- Pydantic for schema enforcement, Click for CLI
- JSONL execution logs, Markdown + JSON reports

## Repository Structure

- `sentinel/` — core code (agents, coordinator, MCP server, tools)
- `sentinel/mcp_server/tools/disk/` — 10 forensic analysis tools
- `sentinel/prompts/` — Analyst and Skeptic system prompts
- `benchmarks/` — accuracy harness with ground truth
- `docs/` — architecture diagram, runbook, dataset docs, spoliation attacks
- `tests/` — 26 unit tests for models and security guards

## How to Run

```bash
pip install -e ".[dev]"
sentinel manifest create m57-jean /evidence/disk/nps-2008-jean.E01 /evidence/disk/nps-2008-jean.E02
sentinel case start m57-jean
sentinel investigate m57-jean --prompt "Identify all user activity and suspicious behavior"
```

## License

Apache 2.0
