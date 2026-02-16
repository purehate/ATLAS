"""Tests for app.services.ingestion.source_config — SourceConfig, SourceConfigManager."""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from app.services.ingestion.source_config import (
    SourceConfig,
    SourceConfigManager,
    SourcesConfig,
)


# ---------------------------------------------------------------------------
# SourceConfig Pydantic model
# ---------------------------------------------------------------------------


class TestSourceConfig:
    def test_defaults(self) -> None:
        sc = SourceConfig(name="test", type="advisory", url="https://example.com")
        assert sc.enabled is True
        assert sc.api_key == ""
        assert sc.reliability_score == 7

    def test_custom_values(self) -> None:
        sc = SourceConfig(
            name="CISA",
            type="advisory",
            url="https://cisa.gov",
            api_key="secret",
            reliability_score=9,
            enabled=False,
        )
        assert sc.name == "CISA"
        assert sc.api_key == "secret"
        assert sc.enabled is False
        assert sc.reliability_score == 9


# ---------------------------------------------------------------------------
# SourcesConfig
# ---------------------------------------------------------------------------


class TestSourcesConfig:
    def test_empty(self) -> None:
        sc = SourcesConfig()
        assert sc.sources == {}
        assert sc.settings == {}

    def test_with_sources(self) -> None:
        source = SourceConfig(name="test", type="api", url="https://test.com")
        sc = SourcesConfig(sources={"test_source": source})
        assert "test_source" in sc.sources


# ---------------------------------------------------------------------------
# SourceConfigManager
# ---------------------------------------------------------------------------


class TestSourceConfigManager:
    def _write_yaml(self, data: dict) -> Path:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yaml.dump(data, f)
        f.close()
        return Path(f.name)

    def test_missing_file_uses_defaults(self) -> None:
        mgr = SourceConfigManager(config_path=Path("/nonexistent/sources.yaml"))
        assert mgr.get_all_sources() == {}

    def test_load_valid_yaml(self) -> None:
        data = {
            "sources": {
                "mitre": {
                    "name": "MITRE ATT&CK",
                    "type": "mitre",
                    "url": "https://attack.mitre.org",
                    "reliability_score": 10,
                }
            },
            "settings": {"debug": True},
        }
        path = self._write_yaml(data)
        mgr = SourceConfigManager(config_path=path)

        assert mgr.get_source_config("mitre") is not None
        assert mgr.get_source_config("mitre").name == "MITRE ATT&CK"
        assert mgr.get_source_config("mitre").reliability_score == 10
        assert mgr.get_setting("debug") is True
        path.unlink()

    def test_is_enabled(self) -> None:
        data = {
            "sources": {
                "enabled_src": {
                    "name": "Enabled",
                    "type": "api",
                    "url": "https://a.com",
                    "enabled": True,
                },
                "disabled_src": {
                    "name": "Disabled",
                    "type": "api",
                    "url": "https://b.com",
                    "enabled": False,
                },
            }
        }
        path = self._write_yaml(data)
        mgr = SourceConfigManager(config_path=path)

        assert mgr.is_enabled("enabled_src") is True
        assert mgr.is_enabled("disabled_src") is False
        assert mgr.is_enabled("nonexistent") is False
        path.unlink()

    def test_get_enabled_sources(self) -> None:
        data = {
            "sources": {
                "a": {
                    "name": "A",
                    "type": "api",
                    "url": "https://a.com",
                    "enabled": True,
                },
                "b": {
                    "name": "B",
                    "type": "api",
                    "url": "https://b.com",
                    "enabled": False,
                },
                "c": {
                    "name": "C",
                    "type": "api",
                    "url": "https://c.com",
                    "enabled": True,
                },
            }
        }
        path = self._write_yaml(data)
        mgr = SourceConfigManager(config_path=path)

        enabled = mgr.get_enabled_sources()
        enabled_keys = [k for k, _ in enabled]
        assert "a" in enabled_keys
        assert "c" in enabled_keys
        assert "b" not in enabled_keys
        path.unlink()

    def test_get_api_key_from_config(self) -> None:
        data = {
            "sources": {
                "test": {
                    "name": "Test",
                    "type": "api",
                    "url": "https://test.com",
                    "api_key": "my_secret_key",
                }
            }
        }
        path = self._write_yaml(data)
        mgr = SourceConfigManager(config_path=path)

        assert mgr.get_api_key("test") == "my_secret_key"
        assert mgr.get_api_key("nonexistent") == ""
        path.unlink()

    def test_get_setting_default(self) -> None:
        mgr = SourceConfigManager(config_path=Path("/nonexistent.yaml"))
        assert mgr.get_setting("missing", default=42) == 42

    def test_reload(self) -> None:
        data = {"sources": {"x": {"name": "X", "type": "api", "url": "https://x.com"}}}
        path = self._write_yaml(data)
        mgr = SourceConfigManager(config_path=path)
        assert mgr.get_source_config("x") is not None

        # Update the file
        data["sources"]["y"] = {"name": "Y", "type": "api", "url": "https://y.com"}
        with open(path, "w") as f:
            yaml.dump(data, f)

        mgr.reload()
        assert mgr.get_source_config("y") is not None
        path.unlink()
