"""Tests for sentinel.models -- proving structural enforcement."""

import pytest
from pydantic import ValidationError
from sentinel.models import Citation, Finding, SkepticVerdict


class TestCitation:
    def test_valid_citation(self):
        c = Citation(artifact="/evidence/disk/case01.E01", locator_type="mft_entry", locator="32704-128-1", excerpt="m57biz.lnk")
        assert c.artifact == "/evidence/disk/case01.E01"

    def test_citation_without_excerpt(self):
        c = Citation(artifact="/evidence/disk/case01.E01", locator_type="registry_key", locator="HKLM\\SOFTWARE\\Microsoft")
        assert c.excerpt is None

    def test_invalid_locator_type(self):
        with pytest.raises(ValidationError):
            Citation(artifact="/evidence/disk/case01.E01", locator_type="magic_pointer", locator="123")


class TestFinding:
    def _make_citation(self) -> Citation:
        return Citation(artifact="/evidence/disk/case01.E01", locator_type="mft_entry", locator="32704-128-1")

    def test_valid_finding(self):
        f = Finding(case_id="case01", title="Test", severity="info",
                    narrative="Test [1].", claim_type="confirmed", evidence=[self._make_citation()])
        assert f.skeptic_verdict == "unverified"
        assert len(f.evidence) == 1

    def test_finding_without_citations_fails(self):
        """THE critical test. No citation = no finding."""
        with pytest.raises(ValidationError, match="at least 1 item"):
            Finding(case_id="case01", title="Hallucinated", severity="high",
                    narrative="Trust me.", claim_type="confirmed", evidence=[])

    def test_finding_with_empty_evidence_list_fails(self):
        with pytest.raises(ValidationError):
            Finding(case_id="case01", title="Empty", severity="critical",
                    narrative="Nothing.", claim_type="confirmed", evidence=[])

    def test_finding_requires_case_id(self):
        with pytest.raises(ValidationError):
            Finding(title="No case", severity="info", narrative="test",
                    claim_type="confirmed", evidence=[self._make_citation()])

    def test_finding_invalid_severity(self):
        with pytest.raises(ValidationError):
            Finding(case_id="case01", title="Bad", severity="catastrophic",
                    narrative="test", claim_type="confirmed", evidence=[self._make_citation()])

    def test_finding_auto_generates_uuid(self):
        f = Finding(case_id="case01", title="Auto", severity="low",
                    narrative="test", claim_type="inferred", evidence=[self._make_citation()])
        assert len(f.finding_id) == 36


class TestSkepticVerdict:
    def test_accept_verdict(self):
        v = SkepticVerdict(finding_id="test-123", verdict="accepted", iteration=0)
        assert v.verdict == "accepted"

    def test_reject_verdict_with_reasons(self):
        v = SkepticVerdict(finding_id="test-123", verdict="rejected",
                           reasons=["Citation [1] MFT entry does not exist"],
                           missing_citations=[Citation(artifact="/evidence/disk/case01.E01",
                                                       locator_type="evt_record", locator="Security.evtx:4688:id=99999")],
                           iteration=1)
        assert len(v.reasons) == 1
