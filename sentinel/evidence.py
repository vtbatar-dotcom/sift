"""Evidence vault management and integrity verification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import CaseManifest, EvidenceFile, SessionRecord

EVIDENCE_ROOT = Path("/evidence")
SESSIONS_DIR = Path("cases")
HASH_BUFFER_SIZE = 8 * 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_BUFFER_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_manifest(manifest_path: Path) -> CaseManifest:
    with open(manifest_path) as f:
        data = json.load(f)
    return CaseManifest(**data)


def create_manifest(case_id: str, evidence_paths: list[Path], description: str = "") -> CaseManifest:
    files = []
    for p in evidence_paths:
        if not p.exists():
            raise FileNotFoundError(f"Evidence file not found: {p}")
        suffix = p.suffix.lower()
        if suffix in (".e01", ".e02", ".dd", ".raw", ".img"):
            file_type = "disk_image"
        elif suffix in (".mem", ".vmem", ".dmp"):
            file_type = "memory_dump"
        else:
            file_type = "supplemental"
        files.append(EvidenceFile(
            path=str(p), sha256=sha256_file(p),
            file_type=file_type, size_bytes=p.stat().st_size,
        ))
    return CaseManifest(case_id=case_id, description=description, evidence_files=files)


def save_manifest(manifest: CaseManifest, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(manifest.model_dump_json(indent=2))


class IntegrityError(Exception):
    """Raised when evidence integrity verification fails."""


class EvidenceVault:
    """Manages evidence integrity across an investigation session."""

    def __init__(self, case_id: str, working_dir: Path | None = None):
        self.case_id = case_id
        self.working_dir = working_dir or Path.cwd()
        self.session: SessionRecord | None = None
        self._manifest: CaseManifest | None = None

    @property
    def case_dir(self) -> Path:
        return self.working_dir / SESSIONS_DIR / self.case_id

    @property
    def session_dir(self) -> Path:
        if self.session is None:
            raise RuntimeError("No active session. Call start_session() first.")
        return self.case_dir / "sessions" / self.session.session_id

    def load_manifest(self, manifest_path: Path | None = None) -> CaseManifest:
        if manifest_path is None:
            manifest_path = self.case_dir / "manifest.json"
        self._manifest = load_manifest(manifest_path)
        return self._manifest

    def start_session(self, manifest: CaseManifest | None = None) -> SessionRecord:
        if manifest is not None:
            self._manifest = manifest
        if self._manifest is None:
            raise RuntimeError("No manifest loaded.")

        start_hashes: dict[str, str] = {}
        mismatches: list[str] = []

        for ef in self._manifest.evidence_files:
            p = Path(ef.path)
            if not p.exists():
                raise FileNotFoundError(f"Evidence file missing: {ef.path}")
            computed = sha256_file(p)
            start_hashes[ef.path] = computed
            if computed != ef.sha256:
                mismatches.append(
                    f"{ef.path}: manifest={ef.sha256[:16]}... computed={computed[:16]}..."
                )

        if mismatches:
            raise IntegrityError(
                f"Evidence integrity check FAILED. "
                f"{len(mismatches)} mismatch(es):\n" + "\n".join(mismatches)
            )

        self.session = SessionRecord(case_id=self.case_id, start_hashes=start_hashes)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._write_session_file("start_hashes.json", start_hashes)
        return self.session

    def end_session(self) -> SessionRecord:
        if self.session is None:
            raise RuntimeError("No active session.")

        end_hashes: dict[str, str] = {}
        mismatches: list[str] = []

        for path, start_hash in self.session.start_hashes.items():
            p = Path(path)
            if not p.exists():
                mismatches.append(f"{path}: FILE MISSING")
                end_hashes[path] = "MISSING"
                continue
            computed = sha256_file(p)
            end_hashes[path] = computed
            if computed != start_hash:
                mismatches.append(path)

        self.session.ended_utc = datetime.now(timezone.utc)
        self.session.end_hashes = end_hashes
        self.session.hash_mismatches = mismatches
        self.session.status = "integrity_violation" if mismatches else "completed"

        self._write_session_file("end_hashes.json", end_hashes)
        self._write_session_file("session.json", self.session.model_dump(mode="json"))

        if mismatches:
            raise IntegrityError(
                f"EVIDENCE INTEGRITY VIOLATION. {len(mismatches)} file(s) modified:\n"
                + "\n".join(mismatches)
            )
        return self.session

    def _write_session_file(self, filename: str, data: dict) -> None:
        path = self.session_dir / filename
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
