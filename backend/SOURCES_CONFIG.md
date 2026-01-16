# ATLAS Data Sources Configuration

ATLAS uses a YAML configuration file (`sources.yaml`) to manage all data sources, similar to BBOT's configuration style. This allows you to:

- Enable/disable sources
- Add API keys for better rate limits
- Configure source-specific settings
- See all sources in one place

## Quick Start

1. **Copy the example config:**
   ```bash
   cp sources.yaml.example sources.yaml
   ```

2. **Edit `sources.yaml` and add your API keys:**
   ```yaml
   sources:
     nist_nvd:
       enabled: true
       api_key: "your-nist-api-key-here"
     
     opencorporates:
       enabled: true
       api_key: "your-opencorporates-api-key-here"
   ```

3. **Check your configuration:**
   ```bash
   docker compose exec backend python scripts/check_sources_config.py
   ```

## Configuration Structure

Each source has the following fields:

```yaml
source_key:
  enabled: true/false          # Enable or disable this source
  name: "Display Name"        # Human-readable name
  type: "advisory|blog|..."    # Source type
  url: "https://..."           # Source URL
  api_key: ""                  # Optional API key
  description: "..."           # Description
  reliability_score: 7         # 1-10 reliability score
  rate_limit: "..."            # Rate limit information
  notes: "..."                 # Additional notes
  api_key_url: "..."           # URL to get API key (if applicable)
```

## Sources That Benefit from API Keys

### NIST NVD (Recommended)
- **Without key**: 5 requests per 30 seconds
- **With key**: 50 requests per 30 seconds
- **Get key**: https://nvd.nist.gov/developers/request-an-api-key

### GitHub Security Advisories (Optional)
- **Without key**: 60 requests per hour
- **With key**: 5000 requests per hour
- **Get key**: https://github.com/settings/tokens

### OpenCorporates (Required for Production)
- **Without key**: Very limited (may not work)
- **With key**: 50 requests/day (free tier)
- **Get key**: https://opencorporates.com/api_accounts/new

## Enabling/Disabling Sources

To disable a source, set `enabled: false`:

```yaml
sources:
  some_source:
    enabled: false  # This source will be skipped during ingestion
```

## Global Settings

The `settings` section contains global configuration:

```yaml
settings:
  ingestion_hour: 2              # Hour of day to run ingestion (0-23)
  score_recalc_hour: 3           # Hour of day to recalculate scores
  default_limit: 50              # Default items to process per source
  backfill_years: 2              # Years of historical data to backfill
  global_rate_limit_per_hour: 1000
```

## Checking Configuration

Use the check script to see all sources and their status:

```bash
docker compose exec backend python scripts/check_sources_config.py
```

This will show:
- All sources (enabled and disabled)
- API key status
- Rate limits
- Reliability scores
- Notes and URLs

## Example Configuration

```yaml
sources:
  nist_nvd:
    enabled: true
    name: "NIST National Vulnerability Database"
    type: "vulnerability"
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: "your-key-here"
    description: "NIST CVE database with CVSS scores"
    reliability_score: 10
    rate_limit: "50 requests per 30 seconds (with key)"
    notes: "Get API key at https://nvd.nist.gov/developers/request-an-api-key"
    api_key_url: "https://nvd.nist.gov/developers/request-an-api-key"
  
  opencorporates:
    enabled: true
    name: "OpenCorporates"
    type: "lookup"
    url: "https://api.opencorporates.com"
    api_key: "your-key-here"
    description: "Company search and validation service"
    reliability_score: 7
    rate_limit: "50 requests/day (free tier)"
    notes: "Get API key at https://opencorporates.com/api_accounts/new"
    api_key_url: "https://opencorporates.com/api_accounts/new"
```

## Security Notes

- **Never commit `sources.yaml` to git** - it's in `.gitignore`
- API keys are stored in plain text in the YAML file
- For production, consider using environment variables or a secrets manager
- The config file is loaded at startup, so restart the backend after changes

## Troubleshooting

### Config file not found
- Make sure `sources.yaml` exists in the `backend/` directory
- Check the path in the error message

### API key not working
- Verify the key is correct (no extra spaces)
- Check if the key has expired
- Some APIs require specific permissions/scopes

### Source not ingesting
- Check if `enabled: true` is set
- Verify the URL is correct
- Check backend logs for errors

## Adding New Sources

To add a new source:

1. Add it to `sources.yaml`:
   ```yaml
   sources:
     my_new_source:
       enabled: true
       name: "My New Source"
       type: "advisory"
       url: "https://example.com"
       api_key: ""
       # ... other fields
   ```

2. Create an ingester in `backend/app/services/ingestion/`
3. Use `get_source_api_key("my_new_source")` to get the API key
4. Use `is_source_enabled("my_new_source")` to check if enabled
5. Add it to the ingestion pipeline

## Integration with Code

The configuration is accessed via:

```python
from app.services.ingestion.source_config import (
    get_source_config,
    is_source_enabled,
    get_source_api_key
)

# Check if source is enabled
if is_source_enabled("nist_nvd"):
    # Get API key
    api_key = get_source_api_key("nist_nvd")
    # Use it in your ingester
```
