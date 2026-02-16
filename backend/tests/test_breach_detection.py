"""Tests for app.services.breach_detection — _calculate_breach_confidence."""

from __future__ import annotations

from app.services.breach_detection import (
    BREACH_KEYWORDS,
    HIGH_CONFIDENCE_SOURCES,
    BreachDetectionService,
)


# ---------------------------------------------------------------------------
# BREACH_KEYWORDS structure
# ---------------------------------------------------------------------------


class TestBreachKeywords:
    def test_has_keywords(self) -> None:
        assert len(BREACH_KEYWORDS) > 10

    def test_common_keywords_present(self) -> None:
        for kw in ["breach", "ransomware", "malware", "phishing attack"]:
            assert kw in BREACH_KEYWORDS, f"Missing keyword: {kw}"


# ---------------------------------------------------------------------------
# HIGH_CONFIDENCE_SOURCES
# ---------------------------------------------------------------------------


class TestHighConfidenceSources:
    def test_has_sources(self) -> None:
        assert len(HIGH_CONFIDENCE_SOURCES) >= 2

    def test_cisa_present(self) -> None:
        assert "CISA Advisory" in HIGH_CONFIDENCE_SOURCES
        assert "CISA KEV" in HIGH_CONFIDENCE_SOURCES


# ---------------------------------------------------------------------------
# _calculate_breach_confidence
# ---------------------------------------------------------------------------


class TestCalculateBreachConfidence:
    def _service(self) -> BreachDetectionService:
        """Create a service with a None db (only testing pure method)."""
        return BreachDetectionService(db=None)  # type: ignore[arg-type]

    def test_no_articles(self) -> None:
        assert self._service()._calculate_breach_confidence([]) == 0

    def test_single_low_confidence_article(self) -> None:
        articles = [{"confidence": 40, "source": "Unknown"}]
        result = self._service()._calculate_breach_confidence(articles)
        assert 0 < result < 50

    def test_multiple_articles_increases_confidence(self) -> None:
        one = [{"confidence": 50, "source": "Unknown"}]
        many = [{"confidence": 50, "source": "Unknown"} for _ in range(5)]
        r1 = self._service()._calculate_breach_confidence(one)
        r5 = self._service()._calculate_breach_confidence(many)
        assert r5 > r1

    def test_high_confidence_source_boost(self) -> None:
        without_cisa = [{"confidence": 60, "source": "Unknown"}]
        with_cisa = [{"confidence": 60, "source": "CISA Advisory"}]
        r_without = self._service()._calculate_breach_confidence(without_cisa)
        r_with = self._service()._calculate_breach_confidence(with_cisa)
        assert r_with > r_without

    def test_max_100(self) -> None:
        articles = [{"confidence": 100, "source": "CISA Advisory"} for _ in range(20)]
        result = self._service()._calculate_breach_confidence(articles)
        assert result <= 100
