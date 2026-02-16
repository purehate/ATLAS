"""Tests for app.utils.security — password hashing and RateLimiter."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.utils.security import get_password_hash, RateLimiter, verify_password


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_and_verify(self) -> None:
        hashed = get_password_hash("mysecret")
        assert verify_password("mysecret", hashed)

    def test_wrong_password(self) -> None:
        hashed = get_password_hash("correct")
        assert not verify_password("wrong", hashed)

    def test_different_hashes_for_same_password(self) -> None:
        h1 = get_password_hash("same")
        h2 = get_password_hash("same")
        # bcrypt uses different salts
        assert h1 != h2

    def test_hash_is_string(self) -> None:
        hashed = get_password_hash("test")
        assert isinstance(hashed, str)
        assert len(hashed) > 20


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_first_request_allowed(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None

        limiter = RateLimiter(mock_redis)
        allowed, remaining = await limiter.check_rate_limit("key", 100, 3600)
        assert allowed is True
        assert remaining == 99
        mock_redis.setex.assert_called_once_with("key", 3600, 1)

    @pytest.mark.asyncio
    async def test_under_limit(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "50"

        limiter = RateLimiter(mock_redis)
        allowed, remaining = await limiter.check_rate_limit("key", 100, 3600)
        assert allowed is True
        assert remaining == 49
        mock_redis.incr.assert_called_once_with("key")

    @pytest.mark.asyncio
    async def test_at_limit(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "100"

        limiter = RateLimiter(mock_redis)
        allowed, remaining = await limiter.check_rate_limit("key", 100, 3600)
        assert allowed is False
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_over_limit(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "150"

        limiter = RateLimiter(mock_redis)
        allowed, remaining = await limiter.check_rate_limit("key", 100, 3600)
        assert allowed is False
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_redis_error_fails_open(self) -> None:
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = ConnectionError("redis down")

        limiter = RateLimiter(mock_redis)
        allowed, remaining = await limiter.check_rate_limit("key", 100, 3600)
        assert allowed is True
        assert remaining is None
