"""
Check Sources Configuration
Validates and displays the current sources.yaml configuration
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.ingestion.source_config import get_source_config_manager


def main():
    """Display source configuration status"""
    manager = get_source_config_manager()
    
    print("=" * 70)
    print("ATLAS Data Sources Configuration")
    print("=" * 70)
    print()
    
    enabled_sources = manager.get_enabled_sources()
    all_sources = manager.get_all_sources()
    
    print(f"Total Sources: {len(all_sources)}")
    print(f"Enabled Sources: {len(enabled_sources)}")
    print()
    
    # Group by type
    by_type = {}
    for key, config in all_sources.items():
        source_type = config.type
        if source_type not in by_type:
            by_type[source_type] = []
        by_type[source_type].append((key, config))
    
    for source_type in sorted(by_type.keys()):
        print(f"\n{source_type.upper()} Sources:")
        print("-" * 70)
        
        for key, config in sorted(by_type[source_type], key=lambda x: x[1].name):
            status = "✓ ENABLED" if config.enabled else "✗ DISABLED"
            api_key_status = "✓ SET" if config.api_key else "✗ NOT SET"
            
            print(f"\n  {config.name} ({key})")
            print(f"    Status: {status}")
            print(f"    URL: {config.url}")
            print(f"    API Key: {api_key_status}")
            if config.api_key_url:
                print(f"    Get API Key: {config.api_key_url}")
            if config.rate_limit:
                print(f"    Rate Limit: {config.rate_limit}")
            print(f"    Reliability: {config.reliability_score}/10")
            if config.notes:
                print(f"    Notes: {config.notes}")
    
    # Show settings
    print("\n" + "=" * 70)
    print("Global Settings:")
    print("-" * 70)
    settings = manager._config.settings if manager._config else {}
    for key, value in sorted(settings.items()):
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 70)
    print("Configuration File Location:")
    print(f"  {manager.config_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
