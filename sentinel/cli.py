"""SIFT Sentinel CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .evidence import EvidenceVault, IntegrityError, create_manifest, save_manifest


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """SIFT Sentinel -- DFIR investigation with structural hallucination prevention."""


@main.group()
def manifest() -> None:
    """Manage evidence manifests."""


@manifest.command("create")
@click.argument("case_id")
@click.argument("evidence_paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--description", "-d", default="", help="Case description")
@click.option("--output", "-o", default=None, type=click.Path(), help="Output path")
def manifest_create(case_id: str, evidence_paths: tuple[str, ...], description: str, output: str | None) -> None:
    """Create a manifest by hashing evidence files."""
    click.echo(f"Creating manifest for case '{case_id}' with {len(evidence_paths)} file(s)...")
    paths = [Path(p) for p in evidence_paths]
    for p in paths:
        click.echo(f"  Hashing {p.name} ({p.stat().st_size / (1024**3):.2f} GB)...")
    m = create_manifest(case_id, paths, description)
    out_path = Path(output) if output else Path(f"cases/{case_id}/manifest.json")
    save_manifest(m, out_path)
    click.echo(f"\nManifest written to {out_path}")
    for ef in m.evidence_files:
        click.echo(f"  {ef.path}: {ef.sha256[:16]}... ({ef.file_type})")


@main.group()
def case() -> None:
    """Manage investigation sessions."""


@case.command("start")
@click.argument("case_id")
@click.option("--manifest", "-m", default=None, type=click.Path(exists=True), help="Path to manifest.json")
def case_start(case_id: str, manifest: str | None) -> None:
    """Start a new investigation session. Verifies evidence integrity."""
    vault = EvidenceVault(case_id)
    manifest_path = Path(manifest) if manifest else None
    try:
        vault.load_manifest(manifest_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Run 'sentinel manifest create' first.", err=True)
        sys.exit(1)
    try:
        session = vault.start_session()
    except IntegrityError as e:
        click.echo(f"INTEGRITY FAILURE:\n{e}", err=True)
        sys.exit(2)
    except FileNotFoundError as e:
        click.echo(f"Evidence file missing: {e}", err=True)
        sys.exit(1)
    click.echo(f"Session started: {session.session_id}")
    click.echo(f"  Case: {session.case_id}")
    click.echo(f"  Files verified: {len(session.start_hashes)}")
    click.echo(f"  Session dir: {vault.session_dir}")
    state_file = Path(f"cases/{case_id}/.active_session")
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({
        "session_id": session.session_id, "case_id": case_id,
    }))
    click.echo("\nEvidence vault is locked. Investigation may proceed.")


@main.command()
@click.argument("case_id")
@click.option("--prompt", "-p", required=True, help="Investigation triage prompt")
@click.option("--max-iterations", default=5, help="Max Skeptic loop iterations per finding")
@click.option("--dry-run", is_flag=True, help="Gather evidence without calling the LLM")
def investigate(case_id: str, prompt: str, max_iterations: int, dry_run: bool) -> None:
    """Run an investigation against a case."""
    import asyncio
    from .investigator import run_investigation

    state_file = Path(f"cases/{case_id}/.active_session")
    if not state_file.exists():
        click.echo("No active session. Run 'sentinel case start' first.", err=True)
        sys.exit(1)

    state = json.loads(state_file.read_text())
    session_dir = Path(f"cases/{case_id}/sessions/{state['session_id']}")
    image_path = "/evidence/disk/nps-2008-jean.E01"

    result = asyncio.run(run_investigation(
        case_id=case_id,
        image_path=image_path,
        prompt=prompt,
        session_dir=session_dir,
        max_iterations=max_iterations,
        dry_run=dry_run,
    ))

    click.echo(f"\n{result.summary()}")


if __name__ == "__main__":
    main()
