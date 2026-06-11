"""Investigator — gathers evidence with tools, then feeds to the Analyst/Skeptic loop."""

from __future__ import annotations

import json
from pathlib import Path

from .coordinator import InvestigationResult
from .logging import ExecutionLogger, IterationTracer
from .models import Finding


def gather_evidence(image_path: str, case_id: str) -> dict:
    """Run all tools and collect results for the Analyst."""
    results = {}

    from sentinel.mcp_server.tools.disk.partitions import list_partitions
    results["partitions"] = list_partitions(image_path, case_id, {}).model_dump(mode="json")

    from sentinel.mcp_server.tools.disk.users import list_user_profiles
    results["user_profiles"] = list_user_profiles(image_path, case_id, {}).model_dump(mode="json")

    from sentinel.mcp_server.tools.disk.registry import query_registry
    results["computer_name"] = query_registry(
        image_path, "SYSTEM", "ControlSet001\\Control\\ComputerName\\ComputerName",
        case_id, {}
    ).model_dump(mode="json")

    from sentinel.mcp_server.tools.disk.prefetch import parse_prefetch
    results["prefetch"] = parse_prefetch(image_path, case_id, {}).model_dump(mode="json")

    from sentinel.mcp_server.tools.disk.services import list_services
    r = list_services(image_path, case_id, {})
    r_filtered = [row for row in r.rows if row.get("image_path")]
    results["services_with_path"] = {"rows": r_filtered[:50], "total": len(r_filtered)}

    from sentinel.mcp_server.tools.disk.runkeys import list_run_keys
    results["run_keys"] = list_run_keys(image_path, case_id, {}).model_dump(mode="json")

    from sentinel.mcp_server.tools.disk.browser import get_browser_history
    r = get_browser_history(image_path, "Jean", "firefox", case_id, {})
    results["browser_history_jean"] = {"rows": r.rows[:50], "total": len(r.rows)}

    from sentinel.mcp_server.tools.disk.mft import get_mft_timeline
    results["recent_mft_activity"] = get_mft_timeline(
        image_path, "2008-07-20", "2008-07-21", case_id, {},
    ).model_dump(mode="json")

    return results


async def run_investigation(
    case_id: str,
    image_path: str,
    prompt: str,
    session_dir: Path,
    max_iterations: int = 5,
    dry_run: bool = False,
) -> InvestigationResult:
    """Full investigation pipeline: gather -> analyze -> skeptic loop."""

    log = ExecutionLogger(session_dir / "execution.jsonl")
    tracer = IterationTracer(session_dir.parent / "iterations")

    print("Gathering evidence from disk image...")
    evidence = gather_evidence(image_path, case_id)
    log.log_session_event("evidence_gathered", {"tools_run": list(evidence.keys())})
    print(f"  Collected data from {len(evidence)} tools")

    if dry_run:
        print("\n=== DRY RUN MODE ===")
        print("Evidence gathered. Skipping LLM calls.")
        for name, data in evidence.items():
            if isinstance(data, dict) and "rows" in data:
                count = len(data["rows"]) if isinstance(data["rows"], list) else "?"
            else:
                count = "N/A"
            print(f"  {name}: {count} rows")
        return InvestigationResult(
            case_id=case_id, accepted=[], unverified=[],
            log_hash=log.compute_log_hash(),
        )

    from .analyst import AnalystAgent
    from .skeptic import SkepticAgent
    from pydantic import ValidationError

    print("\nAnalyst examining evidence...")
    analyst = AnalystAgent(case_id, image_path)
    raw_findings = await analyst.analyze(prompt, evidence)
    print(f"  Analyst produced {len(raw_findings)} finding(s)")
    log.log_session_event("analyst_initial", {"finding_count": len(raw_findings)})

    skeptic = SkepticAgent(case_id)
    accepted = []
    rejected = []

    for i, raw in enumerate(raw_findings):
        try:
            finding = Finding(**raw)
        except ValidationError as e:
            print(f"  Finding {i} failed schema validation: {e.errors()[0]['msg']}")
            log.log_session_event("schema_failure", {"index": i, "errors": str(e)})
            continue

        print(f"\n  Processing: {finding.title}")

        for iteration in range(max_iterations):
            tracer.trace_analyst_draft(finding.finding_id, finding.model_dump(mode="json"), iteration)
            log.log_analyst_draft(finding.finding_id, finding.model_dump(mode="json"), iteration)

            print(f"    Iteration {iteration}: Skeptic reviewing...")
            verdict = await skeptic.review(finding, iteration)

            tracer.trace_skeptic_verdict(finding.finding_id, verdict.verdict, verdict.reasons, iteration)
            log.log_skeptic_verdict(finding.finding_id, verdict.verdict, verdict.reasons, iteration)

            if verdict.verdict == "accepted":
                finding.skeptic_verdict = "accepted"
                finding.iteration = iteration
                tracer.trace_final(finding.finding_id, "accepted")
                print(f"    ACCEPTED at iteration {iteration}")
                accepted.append(finding)
                break

            print(f"    REJECTED: {verdict.reasons}")

            if iteration < max_iterations - 1:
                print(f"    Analyst revising...")
                finding = await analyst.revise(finding, verdict)
                tracer.trace_analyst_revision(
                    finding.finding_id, finding.model_dump(mode="json"), iteration + 1
                )
        else:
            finding.skeptic_verdict = "rejected"
            tracer.trace_final(finding.finding_id, "rejected")
            print(f"    FINAL: rejected after {max_iterations} iterations")
            rejected.append(finding)

    log.log_session_event("investigation_end", {
        "accepted": len(accepted), "rejected": len(rejected),
    })

    return InvestigationResult(
        case_id=case_id, accepted=accepted, unverified=rejected,
        log_hash=log.compute_log_hash(),
    )


def generate_final_report(result, session_dir):
    """Generate the report after an investigation completes."""
    from .reporter import generate_report
    report_path = generate_report(
        result.case_id,
        result.accepted,
        result.unverified,
        session_dir,
        result.log_hash,
    )
    print(f"\nReport written to: {report_path}")
    return report_path
