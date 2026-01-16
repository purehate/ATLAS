# ATLAS - Design Document

**Adversary Technique & Landscape Analysis by Sector**

## 1. Tech Stack Proposal

### Backend
- **Framework**: FastAPI (Python 3.11+)
  - Fast development, automatic OpenAPI docs, async support
  - Built-in validation with Pydantic
- **Database**: PostgreSQL 15
  - Relational data with JSONB for flexible metadata
  - Strong ACID guarantees for data integrity
- **ORM**: SQLAlchemy 2.0 (async)
  - Type-safe queries, migrations via Alembic
- **Job Scheduler**: APScheduler (in-process) + Celery (optional for scale)
  - APScheduler for MVP simplicity (runs in FastAPI worker)
  - Celery + Redis for distributed tasks if needed later
- **Cache/Queue**: Redis 7
  - Caching API responses, rate limiting, job queue (if using Celery)

### Frontend
- **Framework**: React 18 + TypeScript
  - Vite for fast dev server
  - React Query for data fetching/caching
- **UI Library**: Tailwind CSS + shadcn/ui components
  - Modern, accessible, customizable
- **State**: React Query + Zustand (if needed for complex state)

### Infrastructure
- **Containerization**: Docker + Docker Compose
- **Reverse Proxy**: Nginx (optional, can use FastAPI directly for MVP)
- **Monitoring**: Basic logging to stdout (structured JSON logs)

### Python Dependencies (Key)
- `fastapi`, `uvicorn[standard]`
- `sqlalchemy[asyncio]`, `asyncpg`, `alembic`
- `httpx` (async HTTP client for ingestion)
- `beautifulsoup4`, `lxml` (web scraping)
- `pydantic`, `python-dateutil`
- `redis`, `apscheduler`
- `python-jose[cryptography]` (JWT auth)
- `passlib[bcrypt]` (password hashing)

---

## 2. Data Model

### Core Tables

#### `industries`
```sql
- id (PK, UUID)
- name (VARCHAR, unique) -- e.g., "Financial Services"
- code (VARCHAR, unique) -- e.g., "FIN"
- parent_id (FK to industries, nullable) -- for sub-industries
- created_at, updated_at (TIMESTAMP)
```

#### `threat_actor_groups`
```sql
- id (PK, UUID)
- name (VARCHAR, unique) -- e.g., "Lazarus Group"
- aliases (TEXT[]) -- array of known aliases
- mitre_id (VARCHAR, nullable) -- if mapped to MITRE
- description (TEXT)
- first_seen (DATE, nullable)
- last_seen (DATE, nullable)
- metadata (JSONB) -- flexible fields
- created_at, updated_at (TIMESTAMP)
```

#### `mitre_techniques`
```sql
- id (PK, UUID)
- technique_id (VARCHAR, unique) -- e.g., "T1055"
- name (VARCHAR)
- tactic (VARCHAR) -- e.g., "Defense Evasion"
- description (TEXT)
- url (VARCHAR) -- MITRE ATT&CK URL
- metadata (JSONB) -- additional MITRE data
- created_at, updated_at (TIMESTAMP)
```

#### `sources`
```sql
- id (PK, UUID)
- name (VARCHAR) -- e.g., "CISA Advisory"
- type (VARCHAR) -- "advisory", "report", "mitre", "scraped"
- base_url (VARCHAR)
- reliability_score (INTEGER, 1-10) -- source quality weight
- last_checked_at (TIMESTAMP, nullable)
- metadata (JSONB)
- created_at, updated_at (TIMESTAMP)
```

#### `evidence_items` (Core linking table)
```sql
- id (PK, UUID)
- threat_actor_group_id (FK)
- industry_id (FK, nullable) -- if industry-specific
- technique_id (FK, nullable) -- if technique-specific
- source_id (FK)
- source_url (VARCHAR) -- direct link to evidence
- source_title (VARCHAR) -- report/advisory title
- source_date (DATE) -- publication/incident date
- excerpt (TEXT) -- relevant quote/excerpt
- confidence_score (INTEGER, 1-10) -- manual or auto-assigned
- metadata (JSONB) -- raw data, tags, etc.
- created_at, updated_at (TIMESTAMP)
- INDEX on (threat_actor_group_id, industry_id, technique_id)
- INDEX on (source_date DESC)
```

#### `actor_industry_scores` (Precomputed for performance)
```sql
- id (PK, UUID)
- threat_actor_group_id (FK)
- industry_id (FK)
- total_evidence_count (INTEGER)
- weighted_score (FLOAT) -- computed score
- last_calculated_at (TIMESTAMP)
- UNIQUE (threat_actor_group_id, industry_id)
- INDEX on (industry_id, weighted_score DESC)
```

#### `actor_technique_scores` (Precomputed)
```sql
- id (PK, UUID)
- threat_actor_group_id (FK)
- technique_id (FK)
- industry_id (FK, nullable) -- if industry-specific
- evidence_count (INTEGER)
- weighted_score (FLOAT)
- last_calculated_at (TIMESTAMP)
- UNIQUE (threat_actor_group_id, technique_id, industry_id)
- INDEX on (threat_actor_group_id, industry_id, weighted_score DESC)
```

### Relationships
- Many-to-many: Threat Actors ↔ Industries (via evidence_items)
- Many-to-many: Threat Actors ↔ Techniques (via evidence_items)
- Many-to-many: Industries ↔ Techniques (via evidence_items, with actors as context)

---

## 3. Free Data Sources & Ingestion Plan

### Primary Sources (MVP)

#### 1. MITRE ATT&CK
- **Source**: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
- **Update Frequency**: Weekly
- **Ingestion**: Download JSON, parse groups, techniques, relationships
- **Data Extracted**:
  - Threat actor groups (with aliases)
  - Techniques used by each group
  - Industry targeting (if available in descriptions)

#### 2. CISA Advisories
- **Source**: https://www.cisa.gov/news-events/cybersecurity-advisories (RSS/HTML)
- **Update Frequency**: Daily
- **Ingestion**: Scrape HTML or parse RSS, extract:
  - Threat actor names (regex/entity extraction)
  - Affected industries (keywords)
  - Techniques mentioned (MITRE IDs)
  - Publication dates

#### 3. FBI Flash Reports
- **Source**: https://www.ic3.gov/Media/News (HTML scraping)
- **Update Frequency**: Weekly
- **Ingestion**: Scrape HTML, extract actor names, industries, dates

#### 4. OpenCTI (if public API available)
- **Source**: Public OpenCTI instances or GitHub releases
- **Update Frequency**: Weekly
- **Ingestion**: API calls or JSON exports

#### 5. Public Threat Reports (Manual/Scraped)
- **Sources**: 
  - Mandiant reports (public)
  - CrowdStrike reports (public)
  - Unit 42 reports (public)
- **Update Frequency**: Weekly
- **Ingestion**: HTML scraping with attribution, extract:
  - Actor names
  - Industry mentions
  - Technique references

### Ingestion Strategy

1. **Normalization Pipeline**:
   - Extract actor names → match to `threat_actor_groups` (fuzzy matching on aliases)
   - Extract industry keywords → match to `industries` (keyword mapping)
   - Extract technique IDs → match to `mitre_techniques`
   - Create `evidence_items` with source attribution

2. **Deduplication**:
   - Hash on (source_url + threat_actor_group_id + industry_id + technique_id)
   - Skip if exists and source_date hasn't changed

3. **Error Handling**:
   - Log failed sources, continue with others
   - Store raw HTML/JSON in `sources.metadata` for debugging

---

## 4. Scoring Algorithm

### Top 5 Threat Actor Groups per Industry

**Formula**:
```
weighted_score = Σ(evidence_weight × recency_weight × source_reliability)

Where:
- evidence_weight = 1.0 (base)
- recency_weight = 1.0 + (days_ago / 365) * decay_factor
  - decay_factor = 0.5 (evidence older than 1 year gets 50% weight)
  - Max recency_weight = 2.0 (very recent)
- source_reliability = source.reliability_score / 10.0
```

**Steps**:
1. Query `evidence_items` for industry_id
2. Group by `threat_actor_group_id`
3. Calculate weighted_score per group
4. Store in `actor_industry_scores` (precomputed table)
5. Return top 5 ordered by `weighted_score DESC`

### Top Techniques per Actor (within industry context)

**Formula**:
```
technique_score = Σ(evidence_count × recency_weight × source_reliability × industry_match_bonus)

Where:
- industry_match_bonus = 1.5 if evidence has industry_id, else 1.0
```

**Steps**:
1. For each top actor, query `evidence_items` filtered by:
   - `threat_actor_group_id`
   - `industry_id` (if provided)
2. Group by `technique_id`
3. Calculate technique_score
4. Store in `actor_technique_scores`
5. Return top N (configurable, default 10) ordered by score

### Confidence Indicators

**High Confidence**:
- ≥ 5 evidence items
- At least 2 different sources
- At least 1 evidence from last 6 months
- Average source reliability ≥ 7/10

**Medium Confidence**:
- 2-4 evidence items
- At least 1 source
- At least 1 evidence from last 12 months

**Low Confidence**:
- 1 evidence item
- OR all evidence > 12 months old
- OR single low-reliability source

---

## 5. API Endpoints

### Public Endpoints

#### `POST /api/v1/calculate`
**Request**:
```json
{
  "company_name": "Acme Corp",
  "business_vertical": "Financial Services",
  "sub_vertical": "Banking"
}
```

**Response**:
```json
{
  "request_id": "uuid",
  "industry_id": "uuid",
  "results": [
    {
      "threat_actor_group": {
        "id": "uuid",
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA"],
        "mitre_id": "G0032"
      },
      "confidence": "High",
      "weighted_score": 45.2,
      "top_techniques": [
        {
          "technique": {
            "id": "uuid",
            "technique_id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion"
          },
          "score": 12.5,
          "evidence_count": 8
        }
      ],
      "explanations": [
        {
          "source_title": "CISA Advisory AA21-131A",
          "source_url": "https://...",
          "source_date": "2024-01-15",
          "excerpt": "Lazarus Group has been observed targeting financial institutions..."
        }
      ]
    }
  ],
  "metadata": {
    "calculated_at": "2024-01-20T10:00:00Z",
    "total_evidence_items": 127,
    "sources_used": ["CISA", "MITRE ATT&CK", "FBI Flash"]
  }
}
```

#### `GET /api/v1/industries`
List all industries/sub-industries

#### `GET /api/v1/actors`
List all threat actor groups (paginated)

#### `GET /api/v1/techniques`
List all MITRE techniques (filterable by tactic)

### Admin Endpoints (Basic Auth)

#### `POST /api/v1/admin/ingest`
Trigger manual ingestion job

#### `GET /api/v1/admin/ingest/status`
Get ingestion job status

#### `POST /api/v1/admin/recalculate-scores`
Recalculate all precomputed scores

#### `GET /api/v1/admin/stats`
Dashboard stats (evidence counts, source status, etc.)

---

## 6. UI Screens

### Main Screen: Calculator
- **Input Form**:
  - Company name (text input)
  - Business vertical (dropdown/autocomplete)
  - Sub-vertical (dropdown, filtered by vertical)
- **Results Display**:
  - Top 5 actors as cards
  - Each card shows:
    - Actor name + aliases
    - Confidence badge (High/Med/Low)
    - Top 5 techniques (expandable)
    - "Why this result" section (collapsible)
    - Source citations with links
- **Loading State**: Skeleton loaders
- **Error State**: Clear error messages

### Secondary Screens
- **Actor Detail Page**: `/actors/:id`
  - Full profile, all techniques, all industries
- **Industry Detail Page**: `/industries/:id`
  - All associated actors, techniques
- **About Page**: Limitations, data sources, update frequency

---

## 7. Docker Compose Layout

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: threatcalc
      POSTGRES_USER: threatcalc
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U threatcalc"]
      interval: 10s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql+asyncpg://threatcalc:${DB_PASSWORD}@postgres:5432/threatcalc
      REDIS_URL: redis://redis:6379/0
      SECRET_KEY: ${SECRET_KEY}
      ADMIN_USERNAME: ${ADMIN_USERNAME}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
    volumes:
      - ./backend:/app
      - /app/__pycache__
    ports:
      - "6768:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    volumes:
      - ./frontend:/app
      - /app/node_modules
    ports:
      - "3000:3000"
    environment:
      VITE_API_URL: http://localhost:6768/api/v1
    command: npm run dev -- --host

  scheduler:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql+asyncpg://threatcalc:${DB_PASSWORD}@postgres:5432/threatcalc
      REDIS_URL: redis://redis:6379/0
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    command: python -m scheduler.main
    # Runs APScheduler jobs (ingestion, score recalculation)

volumes:
  postgres_data:
  redis_data:
```

---

## 8. Repository Structure

```
applicationX/
├── docker-compose.yml
├── .env.example
├── README.md
├── DESIGN.md (this file)
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── main.py (FastAPI app)
│   ├── config.py (settings)
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   ├── db.py (database connection)
│   │   ├── models.py (SQLAlchemy models)
│   │   ├── schemas.py (Pydantic schemas)
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── v1/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── calculate.py
│   │   │   │   ├── industries.py
│   │   │   │   ├── actors.py
│   │   │   │   └── admin.py
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── calculator.py (scoring logic)
│   │   │   ├── ingestion/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── mitre.py
│   │   │   │   ├── cisa.py
│   │   │   │   ├── fbi.py
│   │   │   │   └── normalizer.py
│   │   │   └── matcher.py (fuzzy matching actors/industries)
│   │   │
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── logging.py
│   │       └── security.py (auth, rate limiting)
│   │
│   ├── scheduler/
│   │   ├── __init__.py
│   │   ├── main.py (APScheduler setup)
│   │   └── jobs.py (ingestion jobs)
│   │
│   └── alembic/
│       ├── versions/
│       └── env.py
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   │
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── index.css
│   │   │
│   │   ├── components/
│   │   │   ├── Calculator.tsx
│   │   │   ├── ResultsCard.tsx
│   │   │   ├── TechniqueList.tsx
│   │   │   ├── ExplanationPanel.tsx
│   │   │   └── ui/ (shadcn components)
│   │   │
│   │   ├── pages/
│   │   │   ├── Home.tsx
│   │   │   ├── ActorDetail.tsx
│   │   │   └── IndustryDetail.tsx
│   │   │
│   │   ├── hooks/
│   │   │   └── useCalculate.ts
│   │   │
│   │   ├── lib/
│   │   │   ├── api.ts (API client)
│   │   │   └── types.ts (TypeScript types)
│   │   │
│   │   └── utils/
│   │       └── constants.ts (industry mappings, etc.)
│
└── scripts/
    ├── init_db.sh (setup initial data)
    └── seed_industries.py (seed industry data)
```

---

## 9. Assumptions & Defaults

### Assumptions
1. **Industry Mapping**: Pre-seed common industries (Financial Services, Healthcare, Energy, etc.) with sub-industries. Users can select from dropdown.
2. **Actor Matching**: Fuzzy string matching on actor names/aliases (using `fuzzywuzzy` or `rapidfuzz`).
3. **Technique Extraction**: Regex patterns to find MITRE IDs (T####) in text.
4. **Source Reliability**: Default scores:
   - MITRE ATT&CK: 10/10
   - CISA: 9/10
   - FBI: 8/10
   - Public reports: 7/10
   - Scraped content: 6/10
5. **Rate Limiting**: 100 requests/hour per IP (public), 1000/hour for admin.
6. **Auth**: Basic HTTP auth for admin endpoints (can upgrade to JWT later).

### Limitations (to display in UI)
- Results are based on historical sector-based inference, not real-time attribution
- Data sources are public and may have gaps
- Confidence scores are estimates based on available evidence
- Industry targeting may be inferred from general reports, not company-specific intel
- Update frequency: Daily for advisories, weekly for reports

---

## 10. MVP Timeline Estimate

**Week 1**:
- Day 1-2: Database setup, models, migrations
- Day 3-4: MITRE ATT&CK ingestion + normalization
- Day 5: Basic calculator API endpoint

**Week 2**:
- Day 1-2: CISA/FBI ingestion
- Day 3: Scoring algorithm implementation
- Day 4: Frontend calculator UI
- Day 5: Scheduler setup, testing, documentation

**Total**: ~10-12 days of focused development for MVP

---

## Next Steps

When you say "start coding," I will:
1. Initialize the project structure
2. Set up Docker Compose with all services
3. Create database models and migrations
4. Implement MITRE ATT&CK ingestion first
5. Build the calculator API endpoint
6. Create the frontend UI
7. Add scheduler for automated ingestion
8. Provide setup instructions and test commands

Ready when you are!
