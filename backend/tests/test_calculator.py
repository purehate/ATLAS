"""Tests for app.services.calculator — _calculate_confidence."""

from __future__ import annotations

from datetime import date, timedelta

from app.schemas import Explanation
from app.services.calculator import CalculatorService


# ---------------------------------------------------------------------------
# _calculate_confidence
# ---------------------------------------------------------------------------


class TestCalculateConfidence:
    def _service(self) -> CalculatorService:
        """Create a service with None db (only testing pure method)."""
        return CalculatorService(db=None)  # type: ignore[arg-type]

    def _recent_explanation(self) -> Explanation:
        return Explanation(
            source_title="Recent",
            source_url="https://example.com",
            source_date=date.today() - timedelta(days=30),
        )

    def _old_explanation(self) -> Explanation:
        return Explanation(
            source_title="Old",
            source_url="https://example.com",
            source_date=date.today() - timedelta(days=365),
        )

    def test_low_single_evidence(self) -> None:
        result = self._service()._calculate_confidence(1, [self._recent_explanation()])
        assert result == "Low"

    def test_medium_two_evidence(self) -> None:
        result = self._service()._calculate_confidence(2, [self._recent_explanation()])
        assert result == "Medium"

    def test_high_many_evidence_recent(self) -> None:
        explanations = [self._recent_explanation(), self._recent_explanation()]
        result = self._service()._calculate_confidence(5, explanations)
        assert result == "High"

    def test_medium_many_evidence_old(self) -> None:
        explanations = [self._old_explanation(), self._old_explanation()]
        result = self._service()._calculate_confidence(5, explanations)
        assert result == "Medium"

    def test_low_zero_evidence(self) -> None:
        result = self._service()._calculate_confidence(0, [])
        assert result == "Low"

    def test_high_threshold_exactly_five(self) -> None:
        explanations = [self._recent_explanation() for _ in range(3)]
        result = self._service()._calculate_confidence(5, explanations)
        assert result == "High"
