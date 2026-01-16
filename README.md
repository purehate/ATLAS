# ATLAS

**Adversary Technique & Landscape Analysis by Sector**

A web application that analyzes business context (company name + industry vertical) and identifies the top threat actor groups most commonly associated with that sector, along with their preferred attack techniques mapped to MITRE ATT&CK.

## Project Overview

This tool provides **sector-based threat intelligence** by:
- Analyzing historical threat actor targeting patterns
- Mapping techniques to MITRE ATT&CK framework
- Providing confidence scores and source citations
- Enabling fast, local queries (no external API dependencies at query time)

**Important**: Results are based on historical sector-based inference, not real-time attribution. This is a research/analytical tool, not a live threat feed.

## Documentation

- **[DESIGN.md](./DESIGN.md)** - Complete technical design (stack, data model, APIs, UI)
- **[DATA_MODEL.md](./DATA_MODEL.md)** - Detailed database schema and relationships
- **[QUICK_START.md](./QUICK_START.md)** - Architecture overview and quick reference
- **[backend/SOURCES_CONFIG.md](./backend/SOURCES_CONFIG.md)** - Data sources configuration guide

## Tech Stack

### Backend
- **FastAPI** (Python 3.11+) - REST API
- **PostgreSQL 15** - Primary database
- **SQLAlchemy 2.0** (async) - ORM
- **Redis 7** - Caching & job queue
- **APScheduler** - Scheduled ingestion jobs

### Frontend
- **React 18 + TypeScript** - UI framework
- **Vite** - Build tool
- **Tailwind CSS + shadcn/ui** - Styling & components

### Infrastructure
- **Docker + Docker Compose** - Containerization
- **Alembic** - Database migrations

## Data Sources (Free/Public)

1. **MITRE ATT&CK** - Threat groups, techniques, relationships
2. **CISA Advisories** - Public cybersecurity advisories
3. **FBI Flash Reports** - IC3 public reports
4. **Public Threat Reports** - Mandiant, CrowdStrike, Unit 42 (scraped with attribution)

## Data Flow

```
┌──────────────┐
│  Scheduler   │ → Downloads/scrapes sources
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Normalizer  │ → Extracts actors, industries, techniques
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  PostgreSQL  │ → Stores evidence_items, precomputed scores
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Calculator  │ → Queries scores, returns top 5 actors
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Frontend   │ → Displays results with citations
└──────────────┘
```

## Core Features

### MVP Features
- Industry/vertical selection (dropdown)
- Top 5 threat actor groups per industry
- Top techniques per actor (ranked)
- MITRE ATT&CK mapping (tactic + technique IDs)
- Source citations with links
- Confidence indicators (High/Med/Low)
- Automated daily/weekly ingestion
- Admin endpoints for manual triggers

### Future Enhancements
- Real-time threat feed integration
- User-submitted evidence (with moderation)
- Advanced filtering (date ranges, source types)
- Export reports (PDF/JSON)
- API key authentication for programmatic access

## 📁 Project Structure

```
applicationX/
├── backend/          # FastAPI application
│   ├── app/         # Main application code
│   ├── scheduler/   # Ingestion jobs
│   └── alembic/     # Database migrations
├── frontend/        # React application
├── scripts/         # Utility scripts
├── docker-compose.yml
└── .env.example     # Environment variables template
```

## Getting Started

### Configuration

**Data Sources Configuration (BBOT-style)**

ATLAS uses a `sources.yaml` file to manage all data sources and API keys in one place:

```bash
cd backend
cp sources.yaml.example sources.yaml
# Edit sources.yaml and add your API keys (optional but recommended)
```

**Check your configuration:**
```bash
docker compose exec backend python scripts/check_sources_config.py
```

See [backend/SOURCES_CONFIG.md](backend/SOURCES_CONFIG.md) for detailed documentation.

**Sources that benefit from API keys:**
- **NIST NVD**: 5 req/30s → 50 req/30s with key
- **GitHub Security**: 60 req/hour → 5000 req/hour with key  
- **OpenCorporates**: Required for company lookup

### Prerequisites
- Docker & Docker Compose
- Ubuntu 24 (or compatible Linux)
- 4GB+ RAM recommended

### Setup (After Code Generation)

1. **Copy environment file**:
   ```bash
   cp .env.example .env
   # Edit .env with your passwords and keys
   ```

2. **Start services**:
   ```bash
   docker-compose up -d
   ```

3. **Run migrations**:
   ```bash
   docker-compose exec backend alembic upgrade head
   ```

4. **Seed initial data**:
   ```bash
   docker-compose exec backend python scripts/seed_industries.py
   docker-compose exec backend python scripts/ingest_mitre.py
   ```

5. **Access application**:
   - Frontend: http://localhost:3001
   - Backend API: http://localhost:6768
   - API Docs: http://localhost:6768/docs

## Security

- Input validation on all endpoints
- Rate limiting (100 req/hour public, 1000/hour admin)
- Basic HTTP auth for admin endpoints
- SQL injection protection (ORM)
- Environment variables for secrets
- CORS configured for frontend origin

## 📈 Scoring Algorithm

**Actor-Industry Score**:
- Weighted by: evidence count, recency (decay over 1 year), source reliability
- Formula: `Σ(evidence_weight × recency_weight × source_reliability)`

**Technique Score**:
- Additional industry match bonus (1.5x if industry-specific)
- Ranked per actor within industry context

**Confidence Levels**:
- **High**: ≥5 evidence items, 2+ sources, recent data (6mo), avg reliability ≥7/10
- **Medium**: 2-4 evidence items, 1+ source, data within 12mo
- **Low**: 1 evidence item OR old data OR low-reliability source

## 🧪 Testing

```bash
# Run backend tests
docker-compose exec backend pytest

# Run frontend tests
docker-compose exec frontend npm test

# Integration test (API)
curl -X POST http://localhost:6768/api/v1/calculate \
  -H "Content-Type: application/json" \
  -d '{"company_name": "Test Corp", "business_vertical": "Financial Services", "sub_vertical": "Banking"}'
```

## Limitations & Disclaimers

- **Not real-time**: Data is refreshed daily/weekly, not in real-time
- **Sector-based inference**: Results are based on industry patterns, not company-specific intel
- **Public sources only**: Relies on free/public data; may have gaps
- **Confidence estimates**: Scores are approximations based on available evidence
- **No attribution**: This tool does not attribute attacks to specific actors

## Contributing

This is a private project. For questions or issues, contact the project maintainer.

## License

[Specify license if applicable]

---

## Next Steps

**Ready to build?** Say **"start coding"** and I'll generate the complete implementation!

The code will be generated incrementally:
1. Project structure & Docker setup
2. Database models & migrations
3. MITRE ATT&CK ingestion
4. Calculator API endpoint
5. Frontend UI
6. Scheduler & additional sources
7. Testing & documentation

---

**Status**: Design Phase Complete - Awaiting "start coding" command
