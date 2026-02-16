"""Tests for config — fix_database_url and Settings."""

from __future__ import annotations

from config import fix_database_url, Settings


# ---------------------------------------------------------------------------
# fix_database_url
# ---------------------------------------------------------------------------


class TestFixDatabaseUrl:
    def test_plain_password(self) -> None:
        url = "postgresql+asyncpg://user:plain@localhost:5432/db"
        assert fix_database_url(url) == url

    def test_special_chars_encoded(self) -> None:
        url = "postgresql+asyncpg://user:p@ss!word@localhost:5432/db"
        result = fix_database_url(url)
        # The @ and ! in password should be encoded
        assert "localhost:5432/db" in result
        assert result.startswith("postgresql+asyncpg://user:")

    def test_already_encoded_not_double_encoded(self) -> None:
        url = "postgresql+asyncpg://user:p%40ss%21word@localhost:5432/db"
        result = fix_database_url(url)
        # Should keep the already-encoded password as-is
        assert "p%40ss%21word" in result

    def test_no_auth(self) -> None:
        url = "postgresql+asyncpg://localhost:5432/db"
        assert fix_database_url(url) == url

    def test_empty_string(self) -> None:
        assert fix_database_url("") == ""

    def test_invalid_url_returns_original(self) -> None:
        url = "not-a-url"
        assert fix_database_url(url) == url


# ---------------------------------------------------------------------------
# Settings defaults
# ---------------------------------------------------------------------------


class TestSettings:
    def test_default_rate_limits(self) -> None:
        s = Settings()
        assert s.api_rate_limit_per_hour == 100
        assert s.admin_rate_limit_per_hour == 1000

    def test_default_reliability_scores(self) -> None:
        s = Settings()
        assert s.source_reliability_mitre == 10
        assert s.source_reliability_cisa == 9
        assert s.source_reliability_fbi == 8
        assert s.source_reliability_public_reports == 7
        assert s.source_reliability_scraped == 6

    def test_default_scoring_algorithm(self) -> None:
        s = Settings()
        assert s.recency_decay_factor == 0.5
        assert s.industry_match_bonus == 1.5

    def test_default_schedule(self) -> None:
        s = Settings()
        assert s.ingestion_schedule_hour == 2
        assert s.score_recalculation_schedule_hour == 3
