# Data Model Details

## Entity Relationship Diagram (Text)

```
┌─────────────────┐
│   industries    │
├─────────────────┤
│ id (PK)         │
│ name            │◄──┐
│ code            │   │
│ parent_id (FK)  │───┘ (self-reference for sub-industries)
└─────────────────┘
        │
        │ 1:N
        │
        ▼
┌─────────────────────────────────┐
│      evidence_items              │
├─────────────────────────────────┤
│ id (PK)                         │
│ threat_actor_group_id (FK) ────┼──┐
│ industry_id (FK) ──────────────┼──┤
│ technique_id (FK) ──────────────┼──┤
│ source_id (FK) ─────────────────┼──┤
│ source_url                      │  │
│ source_title                    │  │
│ source_date                     │  │
│ excerpt                         │  │
│ confidence_score                │  │
└─────────────────────────────────┘  │
        │                            │
        │                            │
        ▼                            │
┌─────────────────┐                 │
│  sources        │                 │
├─────────────────┤                 │
│ id (PK)         │─────────────────┘
│ name            │
│ type            │
│ reliability_score│
└─────────────────┘
        │
        │
        ▼
┌─────────────────┐
│ threat_actor_   │
│    groups       │
├─────────────────┤
│ id (PK)         │◄──┐
│ name            │   │
│ aliases[]       │   │
│ mitre_id        │   │
└─────────────────┘   │
        │             │
        │ 1:N         │
        │             │
        └─────────────┘
        │
        │
        ▼
┌─────────────────┐
│ mitre_techniques│
├─────────────────┤
│ id (PK)         │◄──┐
│ technique_id    │   │
│ name            │   │
│ tactic          │   │
└─────────────────┘   │
                      │
                      │
        ┌─────────────┘
        │
        │
        ▼
┌─────────────────────────────┐
│  actor_industry_scores      │ (Precomputed)
├─────────────────────────────┤
│ threat_actor_group_id (FK)  │
│ industry_id (FK)            │
│ weighted_score              │
│ total_evidence_count        │
└─────────────────────────────┘

┌─────────────────────────────┐
│  actor_technique_scores     │ (Precomputed)
├─────────────────────────────┤
│ threat_actor_group_id (FK)  │
│ technique_id (FK)           │
│ industry_id (FK, nullable)  │
│ weighted_score              │
│ evidence_count              │
└─────────────────────────────┘
```

## Key Indexes

```sql
-- Performance indexes
CREATE INDEX idx_evidence_actor_industry_tech 
  ON evidence_items(threat_actor_group_id, industry_id, technique_id);

CREATE INDEX idx_evidence_source_date 
  ON evidence_items(source_date DESC);

CREATE INDEX idx_actor_industry_score 
  ON actor_industry_scores(industry_id, weighted_score DESC);

CREATE INDEX idx_actor_technique_score 
  ON actor_technique_scores(threat_actor_group_id, industry_id, weighted_score DESC);

-- Full-text search (optional, for future)
CREATE INDEX idx_evidence_excerpt_fts 
  ON evidence_items USING gin(to_tsvector('english', excerpt));
```

## Sample Data Flow

### 1. Ingestion Example

**Input** (CISA Advisory):
```
Title: "Lazarus Group Targets Financial Institutions"
Date: 2024-01-15
URL: https://www.cisa.gov/...
Content: "Lazarus Group (also known as HIDDEN COBRA) has been 
          observed using T1055 (Process Injection) and T1071 
          (Application Layer Protocol) to target banks..."
```

**Processing**:
1. Extract actor: "Lazarus Group" → match to `threat_actor_groups` (fuzzy match)
2. Extract industry: "Financial Institutions" → match to `industries` (keyword: "Banking")
3. Extract techniques: "T1055", "T1071" → match to `mitre_techniques`
4. Create evidence_items:
   - `threat_actor_group_id`: UUID for "Lazarus Group"
   - `industry_id`: UUID for "Banking"
   - `technique_id`: UUID for "T1055" (one row)
   - `technique_id`: UUID for "T1071" (another row)
   - `source_id`: UUID for "CISA Advisory"
   - `source_url`: "https://www.cisa.gov/..."
   - `source_date`: 2024-01-15
   - `excerpt`: "Lazarus Group... targeting banks..."

### 2. Calculation Example

**Input**:
```json
{
  "company_name": "Acme Bank",
  "business_vertical": "Financial Services",
  "sub_vertical": "Banking"
}
```

**Processing**:
1. Match "Banking" → `industry_id`
2. Query `actor_industry_scores` WHERE `industry_id` = X
3. Order by `weighted_score DESC`, LIMIT 5
4. For each actor, query `actor_technique_scores` WHERE `threat_actor_group_id` = Y AND `industry_id` = X
5. Order by `weighted_score DESC`, LIMIT 10
6. Query `evidence_items` for citations (source_url, source_title, excerpt)

**Output**: Top 5 actors with techniques and explanations

## Data Quality Considerations

### Deduplication
- Hash on: `md5(source_url + threat_actor_group_id + COALESCE(industry_id::text, '') + COALESCE(technique_id::text, ''))`
- If hash exists and `source_date` unchanged, skip insert

### Actor Name Normalization
- Store canonical name in `threat_actor_groups.name`
- Store aliases in `threat_actor_groups.aliases[]`
- Match incoming names using:
  1. Exact match on name
  2. Exact match on aliases
  3. Fuzzy match (Levenshtein distance < 3) on name/aliases
  4. If no match, create new group (with manual review flag)

### Industry Keyword Mapping
- Pre-defined mapping table (or JSONB in `industries.metadata`):
  ```json
  {
    "keywords": ["bank", "banking", "financial institution", "credit union"],
    "synonyms": ["fintech", "financial services"]
  }
  ```
- Match using keyword search + fuzzy matching

### Technique ID Extraction
- Regex: `T\d{4}` (e.g., "T1055")
- Also handle sub-techniques: `T1055.001`
- Match to `mitre_techniques.technique_id`

## Migration Strategy

### Initial Setup
1. Create all tables (Alembic migration)
2. Seed `industries` (common verticals/sub-verticals)
3. Seed `mitre_techniques` (from MITRE ATT&CK JSON)
4. Seed `sources` (CISA, FBI, MITRE, etc.)
5. Run initial ingestion

### Ongoing Updates
1. Daily: Ingest CISA/FBI (new advisories)
2. Weekly: Ingest MITRE ATT&CK (updated groups/techniques)
3. After ingestion: Recalculate scores
4. Manual: Review new actor groups (if auto-created)
