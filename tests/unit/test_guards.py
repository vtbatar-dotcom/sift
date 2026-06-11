"""Tests for sentinel.mcp_server.guards -- proving architectural safety."""

import pytest
from sentinel.mcp_server.guards import (
    PathGuardError, ShellInjectionError, OutputTruncated,
    bound_rows, check_output_size, safe_subprocess_args, validate_evidence_path,
    EVIDENCE_ROOT,
)
from pathlib import Path


class TestPathGuard:
    def test_rejects_path_outside_evidence(self):
        with pytest.raises(PathGuardError, match="outside the evidence vault"):
            validate_evidence_path("/etc/passwd")

    def test_rejects_dot_dot_traversal(self):
        with pytest.raises(PathGuardError):
            validate_evidence_path("/evidence/../etc/passwd")

    def test_rejects_home_directory(self):
        with pytest.raises(PathGuardError):
            validate_evidence_path("/home/ubuntu/something")

    def test_rejects_nonexistent_evidence_file(self):
        with pytest.raises(PathGuardError, match="does not exist"):
            validate_evidence_path("/evidence/disk/nonexistent.E01")

    @pytest.mark.skipif(not Path("/evidence").exists(), reason="No evidence vault mounted")
    def test_accepts_valid_evidence_path(self):
        files = list(Path("/evidence").rglob("*"))
        if files:
            result = validate_evidence_path(files[0])
            assert result.is_relative_to(EVIDENCE_ROOT)


class TestOutputBounding:
    def test_rows_under_limit(self):
        rows = [{"a": i} for i in range(100)]
        bounded, truncated = bound_rows(rows, max_rows=200)
        assert len(bounded) == 100
        assert truncated is False

    def test_rows_over_limit(self):
        rows = [{"a": i} for i in range(500)]
        bounded, truncated = bound_rows(rows, max_rows=200)
        assert len(bounded) == 200
        assert truncated is True

    def test_output_size_over_limit(self):
        with pytest.raises(OutputTruncated):
            check_output_size(b"x" * 3_000_000, max_bytes=2_000_000)


class TestSubprocessSafety:
    def test_allowed_binary(self):
        argv = safe_subprocess_args("fls", ["-r", "/evidence/disk/test.E01"])
        assert argv[0] == "/usr/bin/fls"

    def test_unknown_binary_rejected(self):
        with pytest.raises(ShellInjectionError, match="not in the allowed list"):
            safe_subprocess_args("rm", ["-rf", "/"])

    def test_shell_metachar_semicolon(self):
        with pytest.raises(ShellInjectionError):
            safe_subprocess_args("fls", ["-r", "/evidence; rm -rf /"])

    def test_shell_metachar_pipe(self):
        with pytest.raises(ShellInjectionError):
            safe_subprocess_args("fls", ["-r", "/evidence | cat /etc/shadow"])

    def test_shell_metachar_backtick(self):
        with pytest.raises(ShellInjectionError):
            safe_subprocess_args("fls", ["`whoami`"])

    def test_shell_metachar_dollar(self):
        with pytest.raises(ShellInjectionError):
            safe_subprocess_args("fls", ["${PATH}"])

    def test_clean_args_pass(self):
        argv = safe_subprocess_args("icat", ["-i", "ewf", "-o", "63", "/evidence/disk/case01.E01", "32704-128-1"])
        assert len(argv) == 7
