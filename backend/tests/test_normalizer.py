"""Tests for app.services.ingestion.normalizer — _generate_hash, _calculate_confidence_score."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from app.services.ingestion.normalizer import Normalizer


# ---------------------------------------------------------------------------
# _generate_hash
# ---------------------------------------------------------------------------


class TestGenerateHash:
    def _normalizer(self) -> Normalizer:
        return Normalizer(db=None)  # type: ignore[arg-type]

    def test_deterministic(self) -> None:
        n = self._normalizer()
        actor_id = uuid4()
        h1 = n._generate_hash("https://example.com", actor_id, None, None)
        h2 = n._generate_hash("https://example.com", actor_id, None, None)
        assert h1 == h2

    def test_different_urls_differ(self) -> None:
        n = self._normalizer()
        actor_id = uuid4()
        h1 = n._generate_hash("https://a.com", actor_id, None, None)
        h2 = n._generate_hash("https://b.com", actor_id, None, None)
        assert h1 != h2

    def test_different_actors_differ(self) -> None:
        n = self._normalizer()
        h1 = n._generate_hash("https://example.com", uuid4(), None, None)
        h2 = n._generate_hash("https://example.com", uuid4(), None, None)
        assert h1 != h2

    def test_with_industry_and_technique(self) -> None:
        n = self._normalizer()
        actor_id = uuid4()
        ind_id = uuid4()
        tech_id = uuid4()
        h = n._generate_hash("https://example.com", actor_id, ind_id, tech_id)
        assert isinstance(h, str)
        assert len(h) == 32  # MD5 hex digest

    def test_none_ids_consistent(self) -> None:
        n = self._normalizer()
        actor_id = uuid4()
        h1 = n._generate_hash("https://example.com", actor_id, None, None)
        h2 = n._generate_hash("https://example.com", actor_id, None, uuid4())
        assert h1 != h2


# ---------------------------------------------------------------------------
# _calculate_confidence_score
# ---------------------------------------------------------------------------


class TestCalculateConfidenceScore:
    def _normalizer(self) -> Normalizer:
        return Normalizer(db=None)  # type: ignore[arg-type]

    def test_normal_score(self) -> None:
        source = SimpleNamespace(reliability_score=7)
        assert self._normalizer()._calculate_confidence_score(source) == 7

    def test_max_clamp(self) -> None:
        source = SimpleNamespace(reliability_score=15)
        assert self._normalizer()._calculate_confidence_score(source) == 10

    def test_min_clamp(self) -> None:
        source = SimpleNamespace(reliability_score=0)
        assert self._normalizer()._calculate_confidence_score(source) == 1

    def test_negative_clamp(self) -> None:
        source = SimpleNamespace(reliability_score=-5)
        assert self._normalizer()._calculate_confidence_score(source) == 1
