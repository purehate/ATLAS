# Quick Start Guide

## Architecture Overview

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Frontend  │─────▶│   Backend   │─────▶│  PostgreSQL │
│  (React)    │      │  (FastAPI)  │      │             │
└─────────────┘      └─────────────┘      └─────────────┘
                            │
                            ▼
                      ┌─────────────┐
                      │    Redis    │
                      │  (Cache/Q)  │
                      └─────────────┘
                            ▲
                            │
                      ┌─────────────┐
                      │  Scheduler  │
                      │ (Ingestion) │
                      └─────────────┘
```

## Data Flow

1. **Ingestion** (Scheduler):
   - Downloads MITRE ATT&CK JSON
   - Scrapes CISA/FBI advisories
   - Normalizes data → stores in PostgreSQL
   - Creates evidence_items linking actors, industries, techniques

2. **Calculation** (API):
   - User submits: company + vertical + sub-vertical
   - Backend matches to industry_id
   - Queries precomputed scores (or calculates on-the-fly)
   - Returns top 5 actors with techniques and citations

3. **Scoring** (Background):
   - Runs after ingestion
   - Precomputes `actor_industry_scores` and `actor_technique_scores`
   - Updates confidence indicators

## Key Design Decisions

### Why PostgreSQL?
- Relational data (actors, industries, techniques) with clear relationships
- JSONB for flexible metadata without sacrificing structure
- Strong consistency for evidence tracking

### Why FastAPI?
- Fast development (auto-docs, validation)
- Async support for concurrent ingestion
- Python ecosystem (scraping, NLP libraries)

### Why Precomputed Scores?
- Fast API responses (< 100ms)
- Can recalculate on schedule or on-demand
- Trade-off: slight staleness acceptable for speed

### Why APScheduler (not Celery)?
- Simpler for MVP (no separate worker process)
- Sufficient for daily/weekly jobs
- Can migrate to Celery if scale requires

## Data Source Strategy

### Phase 1 (MVP):
- MITRE ATT&CK (structured JSON)
- CISA Advisories (HTML scraping)
- FBI Flash Reports (HTML scraping)

### Phase 2 (Future):
- OpenCTI public API
- Additional public threat reports
- User-submitted evidence (with moderation)

## Scoring Logic Summary

**Actor-Industry Score**:
```
For each evidence item:
  base_score = 1.0
  recency_multiplier = 1.0 + (days_ago / 365) * 0.5
  source_multiplier = source_reliability / 10.0
  weighted_score += base_score × recency_multiplier × source_multiplier
```

**Technique Score** (per actor):
```
For each technique evidence:
  base_score = evidence_count
  recency_multiplier = (same as above)
  source_multiplier = (same as above)
  industry_bonus = 1.5 if industry-specific, else 1.0
  technique_score += base_score × recency_multiplier × source_multiplier × industry_bonus
```

## Security Considerations

1. **Input Validation**: Pydantic schemas validate all inputs
2. **Rate Limiting**: Redis-backed rate limiter (per IP)
3. **SQL Injection**: SQLAlchemy ORM prevents injection
4. **API Keys**: Stored in .env, never committed
5. **Admin Auth**: Basic HTTP auth (upgradeable to JWT)
6. **CORS**: Configured for frontend origin only

## Performance Optimizations

1. **Database Indexes**: On foreign keys, date fields, score fields
2. **Precomputed Scores**: Avoid real-time calculations
3. **Redis Caching**: Cache API responses (TTL: 1 hour)
4. **Connection Pooling**: Asyncpg connection pool
5. **Pagination**: For large result sets

## Monitoring & Debugging

- Structured JSON logs (stdout)
- Health check endpoints (`/health`, `/api/v1/admin/stats`)
- Ingestion job status tracking
- Source last_checked_at timestamps

## Deployment Notes

- All services in Docker Compose for local dev
- Production: Same compose file can be used, or migrate to K8s
- Database backups: Use PostgreSQL pg_dump (cron job)
- Environment variables: Use .env file (never commit)

---

**Ready to code?** Say "start coding" and I'll generate the full implementation!
