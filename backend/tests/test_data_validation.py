"""Tests for app.services.ingestion.data_validation — DataValidator.validate_evidence_item."""

from __future__ import annotations

from datetime import date, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.ingestion.data_validation import DataValidator


def _make_evidence(**overrides) -> SimpleNamespace:
    """Create a fake evidence item with sensible defaults."""
    defaults = {
        "source_title": "CISA Advisory AA24-001",
        "source_url": "https://cisa.gov/advisories/aa24-001",
        "source_date": date.today() - timedelta(days=7),
        "threat_actor_group_id": uuid4(),
        "technique_id": uuid4(),
        "industry_id": uuid4(),
        "excerpt": "APT28 targeting financial sector with spearphishing campaigns.",
        "confidence_score": 8,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# validate_evidence_item
# ---------------------------------------------------------------------------


class TestValidateEvidenceItem:
    def _validator(self) -> DataValidator:
        return DataValidator(db=None)  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_valid_item(self) -> None:
        result = await self._validator().validate_evidence_item(_make_evidence())
        assert result["valid"] is True
        assert result["issues"] == []

    @pytest.mark.asyncio
    async def test_missing_title(self) -> None:
        evidence = _make_evidence(source_title="")
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is False
        assert any("title" in i.lower() for i in result["issues"])

    @pytest.mark.asyncio
    async def test_short_title(self) -> None:
        evidence = _make_evidence(source_title="Hi")
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_missing_url(self) -> None:
        evidence = _make_evidence(source_url=None)
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_invalid_url_format(self) -> None:
        evidence = _make_evidence(source_url="ftp://bad.com")
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is True  # warning, not error
        assert any("url" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_missing_date(self) -> None:
        evidence = _make_evidence(source_date=None)
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_future_date(self) -> None:
        evidence = _make_evidence(source_date=date.today() + timedelta(days=30))
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is False
        assert any("future" in i.lower() for i in result["issues"])

    @pytest.mark.asyncio
    async def test_very_old_date_warning(self) -> None:
        evidence = _make_evidence(source_date=date(1999, 12, 31))
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is True
        assert any("old" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_missing_actor(self) -> None:
        evidence = _make_evidence(threat_actor_group_id=None)
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_no_technique_or_industry_warning(self) -> None:
        evidence = _make_evidence(technique_id=None, industry_id=None)
        result = await self._validator().validate_evidence_item(evidence)
        assert result["valid"] is True
        assert any(
            "technique" in w.lower() or "industry" in w.lower()
            for w in result["warnings"]
        )

    @pytest.mark.asyncio
    async def test_short_excerpt_warning(self) -> None:
        evidence = _make_evidence(excerpt="short")
        result = await self._validator().validate_evidence_item(evidence)
        assert any("excerpt" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_low_confidence_warning(self) -> None:
        evidence = _make_evidence(confidence_score=2)
        result = await self._validator().validate_evidence_item(evidence)
        assert any("confidence" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_score_decreases_with_issues(self) -> None:
        good = await self._validator().validate_evidence_item(_make_evidence())
        bad = await self._validator().validate_evidence_item(
            _make_evidence(source_title="", source_url=None, source_date=None)
        )
        assert good["score"] > bad["score"]
