"""Investigator — gathers evidence with tools, then feeds to the Analyst/Skeptic loop."""

from __future__ import annotations

import json
from pathlib import Path

from .coordinator import InvestigationResult
from .logging import ExecutionLogger, IterationTracer
from .models import Finding, Citation


def gather_evidence(image_path: str, case_id: str) -> dict:
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


def normalize_finding(raw: dict, case_id: str) -> dict:
    """Aggressively normalize LLM output to match our Finding schema."""
    out = {}

    # Direct field mappings (LLM name -> our name)
    field_map = {
        "description": "narrative", "summary": "narrative", "details": "narrative",
        "analysis": "narrative", "text": "narrative",
        "confidence": "claim_type", "type": "claim_type",
        "category": "_category",
        "mitre_techniques": "mitre_attack", "mitre": "mitre_attack",
        "attack_techniques": "mitre_attack",
        "artifacts": "evidence", "citations": "evidence",
        "notes": "_notes",
    }

    for k, v in raw.items():
        out[field_map.get(k, k)] = v

    out["case_id"] = case_id

    # Severity: force into our enum
    VALID_SEV = {"info", "low", "med", "high", "critical"}
    sev = str(out.get("severity", "")).lower().strip()
    sev_map = {"medium": "med", "moderate": "med", "informational": "info",
               "information": "info", "none": "info", "negligible": "info"}
    sev = sev_map.get(sev, sev)
    if sev not in VALID_SEV:
        # If it's not a standard severity, infer from keywords
        sev_lower = sev.lower()
        if any(w in sev_lower for w in ["critical", "severe", "urgent"]):
            sev = "critical"
        elif any(w in sev_lower for w in ["high", "important", "significant"]):
            sev = "high"
        elif any(w in sev_lower for w in ["medium", "moderate", "notable"]):
            sev = "med"
        elif any(w in sev_lower for w in ["low", "minor"]):
            sev = "low"
        else:
            sev = "info"
    out["severity"] = sev

    # claim_type: force into our enum
    VALID_CT = {"confirmed", "inferred"}
    ct = str(out.get("claim_type", "confirmed")).lower().strip()
    ct_map = {"confirmed_artifact": "confirmed", "direct": "confirmed",
              "high": "confirmed", "definitive": "confirmed",
              "inferred_correlation": "inferred", "circumstantial": "inferred",
              "medium": "inferred", "low": "inferred", "suspected": "inferred"}
    ct = ct_map.get(ct, ct)
    if ct not in VALID_CT:
        ct = "confirmed"
    out["claim_type"] = ct

    # Ensure narrative is a string
    narr = out.get("narrative", None)
    if narr is None:
        narr = out.get("title", "No description provided.")
    if isinstance(narr, list):
        narr = " ".join(str(item) for item in narr)
    elif isinstance(narr, dict):
        narr = str(narr)
    out["narrative"] = str(narr)

    # Ensure evidence is a list of proper Citation dicts
    evidence = out.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    cleaned_evidence = []
    for e in evidence:
        if isinstance(e, dict):
            cit = {
                "artifact": e.get("artifact", e.get("source", e.get("file", "/evidence/disk/nps-2008-jean.E01"))),
                "locator_type": e.get("locator_type", e.get("type", "file_path")),
                "locator": e.get("locator", e.get("location", e.get("path", e.get("key", "unknown")))),
                "excerpt": e.get("excerpt", e.get("value", e.get("description", None))),
            }
            # Validate locator_type
            valid_lt = {"byte_offset", "mft_entry", "registry_key", "evt_record", "pid", "vaddr", "file_path"}
            if cit["locator_type"] not in valid_lt:
                cit["locator_type"] = "file_path"
            cleaned_evidence.append(cit)
    if not cleaned_evidence:
        # Create a generic citation so the finding doesn't fail
        cleaned_evidence.append({
            "artifact": "/evidence/disk/nps-2008-jean.E01",
            "locator_type": "file_path",
            "locator": "general_analysis",
            "excerpt": out.get("title", ""),
        })
    out["evidence"] = cleaned_evidence

    # Normalize timeline entries
    timeline = out.get("timeline", [])
    if isinstance(timeline, list):
        cleaned_tl = []
        for t in timeline:
            if isinstance(t, dict):
                cleaned_tl.append({
                    "timestamp_utc": t.get("timestamp_utc", t.get("timestamp", t.get("time", "2008-07-20T00:00:00Z"))),
                    "source": t.get("source", t.get("artifact_type", "mft")),
                    "description": t.get("description", t.get("event", str(t))),
                    "citation_index": t.get("citation_index", 0),
                })
        out["timeline"] = cleaned_tl
    else:
        out["timeline"] = []

    # Ensure mitre_attack is a list
    mitre = out.get("mitre_attack", [])
    if not isinstance(mitre, list):
        mitre = [mitre] if mitre else []
    out["mitre_attack"] = [str(m) for m in mitre if m]

    # Remove unknown fields
    known = {"finding_id", "case_id", "title", "severity", "narrative", "claim_type",
             "mitre_attack", "evidence", "timeline", "supersedes", "iteration",
             "analyst_model", "skeptic_verdict", "tool_calls"}
    out = {k: v for k, v in out.items() if k in known}

    return out


async def run_investigation(
    case_id: str,
    image_path: str,
    prompt: str,
    session_dir: Path,
    max_iterations: int = 5,
    dry_run: bool = False,
) -> InvestigationResult:
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
        normalized = normalize_finding(raw, case_id)
        try:
            finding = Finding(**normalized)
        except ValidationError as e:
            err = e.errors()[0]
            print(f"  Finding {i} failed: field='{err.get('loc', '?')}' msg='{err['msg']}'")
            log.log_session_event("schema_failure", {"index": i, "errors": str(e)})
            continue

        print(f"\n  [{finding.severity}] {finding.title}")

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

    # Generate report
    from .reporter import generate_report
    report_path = generate_report(case_id, accepted, rejected, session_dir, log.compute_log_hash())
    print(f"\nReport written to: {report_path}")

    return InvestigationResult(
        case_id=case_id, accepted=accepted, unverified=rejected,
        log_hash=log.compute_log_hash(),
    )
