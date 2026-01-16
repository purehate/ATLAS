"""
Source Configuration Manager
Loads and manages data source configuration from sources.yaml
Similar to BBOT's config style
"""
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.utils.logging import setup_logging

logger = setup_logging()


class SourceConfig(BaseModel):
    """Configuration for a single data source"""
    enabled: bool = True
    name: str
    type: str
    url: str
    api_key: str = ""
    description: str = ""
    reliability_score: int = 7
    rate_limit: Optional[str] = None
    notes: str = ""
    api_key_url: Optional[str] = None


class SourcesConfig(BaseModel):
    """Container for all source configurations"""
    sources: Dict[str, SourceConfig] = Field(default_factory=dict)
    settings: Dict = Field(default_factory=dict)


class SourceConfigManager:
    """Manages loading and accessing source configurations"""
    
    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            # Default to sources.yaml in backend directory (3 levels up from this file)
            # This file is at: backend/app/services/ingestion/source_config.py
            # sources.yaml is at: backend/sources.yaml
            backend_dir = Path(__file__).parent.parent.parent.parent
            config_path = backend_dir / "sources.yaml"
        self.config_path = config_path
        self._config: Optional[SourcesConfig] = None
        self._load_config()
    
    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            if not self.config_path.exists():
                logger.warning(f"Config file not found: {self.config_path}. Using defaults.")
                self._config = SourcesConfig()
                return
            
            with open(self.config_path, 'r') as f:
                data = yaml.safe_load(f)
            
            # Convert to Pydantic models
            sources_dict = {}
            if 'sources' in data:
                for key, value in data['sources'].items():
                    sources_dict[key] = SourceConfig(**value)
            
            self._config = SourcesConfig(
                sources=sources_dict,
                settings=data.get('settings', {})
            )
            
            logger.info(f"Loaded {len(sources_dict)} source configurations from {self.config_path}")
        except Exception as e:
            logger.error(f"Error loading config file {self.config_path}: {e}")
            self._config = SourcesConfig()
    
    def get_source_config(self, source_key: str) -> Optional[SourceConfig]:
        """Get configuration for a specific source"""
        if not self._config:
            return None
        return self._config.sources.get(source_key)
    
    def is_enabled(self, source_key: str) -> bool:
        """Check if a source is enabled"""
        config = self.get_source_config(source_key)
        if not config:
            return False
        return config.enabled
    
    def get_api_key(self, source_key: str) -> str:
        """Get API key for a source (checks config, then environment variables)"""
        config = self.get_source_config(source_key)
        if not config:
            return ""
        
        # First check config file
        if config.api_key:
            return config.api_key
        
        # Fall back to environment variables (for backward compatibility)
        import os
        env_key = f"{source_key.upper()}_API_KEY"
        return os.getenv(env_key, "")
    
    def get_enabled_sources(self) -> List[tuple[str, SourceConfig]]:
        """Get list of all enabled sources"""
        if not self._config:
            return []
        
        return [
            (key, config) 
            for key, config in self._config.sources.items() 
            if config.enabled
        ]
    
    def get_setting(self, key: str, default=None):
        """Get a global setting value"""
        if not self._config:
            return default
        return self._config.settings.get(key, default)
    
    def reload(self):
        """Reload configuration from file"""
        self._load_config()
    
    def get_all_sources(self) -> Dict[str, SourceConfig]:
        """Get all source configurations (enabled and disabled)"""
        if not self._config:
            return {}
        return self._config.sources


# Global instance
_config_manager: Optional[SourceConfigManager] = None


def get_source_config_manager(config_path: Optional[Path] = None) -> SourceConfigManager:
    """Get the global source config manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = SourceConfigManager(config_path)
    return _config_manager


def get_source_config(source_key: str) -> Optional[SourceConfig]:
    """Convenience function to get a source config"""
    return get_source_config_manager().get_source_config(source_key)


def is_source_enabled(source_key: str) -> bool:
    """Convenience function to check if a source is enabled"""
    return get_source_config_manager().is_enabled(source_key)


def get_source_api_key(source_key: str) -> str:
    """Convenience function to get a source API key"""
    return get_source_config_manager().get_api_key(source_key)
