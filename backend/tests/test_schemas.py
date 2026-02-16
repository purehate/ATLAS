"""Tests for app.schemas — Pydantic request/response validation."""

from __future__ import annotations

from datetime import date
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas import (
    ActorInfo,
    ActorResult,
    CalculateRequest,
    CalculateResponse,
    Explanation,
    IndustryInfo,
    TechniqueInfo,
    TechniqueScore,
    ThreatActorInfo,
)


# ---------------------------------------------------------------------------
# CalculateRequest
# ---------------------------------------------------------------------------


class TestCalculateRequest:
    def test_valid_request(self) -> None:
        req = CalculateRequest(
            company_name="ACME Corp",
            business_vertical="Technology",
        )
        assert req.company_name == "ACME Corp"
        assert req.business_vertical == "Technology"
        assert req.sub_vertical is None

    def test_with_sub_vertical(self) -> None:
        req = CalculateRequest(
            company_name="Test",
            business_vertical="Financial Services",
            sub_vertical="Banking",
        )
        assert req.sub_vertical == "Banking"

    def test_missing_company_name(self) -> None:
        with pytest.raises(ValidationError):
            CalculateRequest(business_vertical="Tech")

    def test_missing_vertical(self) -> None:
        with pytest.raises(ValidationError):
            CalculateRequest(company_name="Test")


# ---------------------------------------------------------------------------
# ThreatActorInfo
# ---------------------------------------------------------------------------


class TestThreatActorInfo:
    def test_valid(self) -> None:
        uid = uuid4()
        info = ThreatActorInfo(
            id=uid,
            name="APT28",
            aliases=["Fancy Bear", "Sofacy"],
            mitre_id="G0007",
        )
        assert info.name == "APT28"
        assert len(info.aliases) == 2

    def test_no_aliases(self) -> None:
        info = ThreatActorInfo(id=uuid4(), name="Unknown", aliases=[])
        assert info.aliases == []


# ---------------------------------------------------------------------------
# TechniqueInfo
# ---------------------------------------------------------------------------


class TestTechniqueInfo:
    def test_valid(self) -> None:
        info = TechniqueInfo(
            id=uuid4(),
            technique_id="T1566",
            name="Phishing",
            tactic="Initial Access",
        )
        assert info.technique_id == "T1566"
        assert info.tactic == "Initial Access"


# ---------------------------------------------------------------------------
# Explanation
# ---------------------------------------------------------------------------


class TestExplanation:
    def test_valid(self) -> None:
        exp = Explanation(
            source_title="CISA Advisory",
            source_url="https://cisa.gov/advisory/123",
            source_date=date(2025, 1, 15),
            excerpt="APT28 targeting...",
        )
        assert exp.source_title == "CISA Advisory"
        assert exp.source_date == date(2025, 1, 15)


# ---------------------------------------------------------------------------
# IndustryInfo
# ---------------------------------------------------------------------------


class TestIndustryInfo:
    def test_valid(self) -> None:
        uid = uuid4()
        info = IndustryInfo(id=uid, name="Technology", code="TECH")
        assert info.name == "Technology"
        assert info.parent_id is None


# ---------------------------------------------------------------------------
# ActorInfo
# ---------------------------------------------------------------------------


class TestActorInfo:
    def test_valid(self) -> None:
        info = ActorInfo(
            id=uuid4(),
            name="APT29",
            aliases=["Cozy Bear"],
            mitre_id="G0016",
            description="Russian state-sponsored actor",
        )
        assert info.name == "APT29"
        assert info.description == "Russian state-sponsored actor"


# ---------------------------------------------------------------------------
# CalculateResponse
# ---------------------------------------------------------------------------


class TestCalculateResponse:
    def test_empty_results(self) -> None:
        resp = CalculateResponse(
            request_id=uuid4(),
            industry_id=None,
            results=[],
            metadata={"calculated_at": "2025-01-15"},
        )
        assert resp.results == []

    def test_with_results(self) -> None:
        actor_id = uuid4()
        tech_id = uuid4()
        resp = CalculateResponse(
            request_id=uuid4(),
            industry_id=uuid4(),
            results=[
                ActorResult(
                    threat_actor_group=ThreatActorInfo(
                        id=actor_id,
                        name="APT28",
                        aliases=[],
                    ),
                    confidence="High",
                    weighted_score=9.5,
                    top_techniques=[
                        TechniqueScore(
                            technique=TechniqueInfo(
                                id=tech_id,
                                technique_id="T1566",
                                name="Phishing",
                                tactic="Initial Access",
                            ),
                            score=5.0,
                            evidence_count=3,
                        )
                    ],
                    explanations=[],
                )
            ],
            metadata={},
        )
        assert len(resp.results) == 1
        assert resp.results[0].confidence == "High"
