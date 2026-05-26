# 0003 — Hybrid database schema: extracted columns + full JSONB

**Status:** Accepted

**Date:** 2026-05-25

## Context

Battlefield needs to store every ShellKnight Run Report in PostgreSQL. The Fleet Grid queries the latest run per machine on every page load, reading hostname, run date, security score, performance score, and IOC alert count. The drill-down view reads the full Run Report. A schema decision was needed.

## Decision

Use a hybrid schema for the `runs` table:

- Extracted columns for Fleet Grid fields: `hostname`, `run_date`, `security_score`, `performance_score`, `ioc_alerts` — all indexed, queried directly by SQL without touching JSONB.
- Full `report JSONB` column containing the complete Run Report for drill-down views.
- `tenant_id` foreign key to a `tenants` table (one row per Tenant/API Key).
- `created_at` timestamp for insertion order.

```sql
CREATE TABLE tenants (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    api_key    TEXT NOT NULL UNIQUE
);

CREATE TABLE runs (
    id                SERIAL PRIMARY KEY,
    tenant_id         INTEGER NOT NULL REFERENCES tenants(id),
    hostname          TEXT NOT NULL,
    run_date          TIMESTAMPTZ NOT NULL,
    security_score    INTEGER,
    performance_score INTEGER,
    ioc_alerts        INTEGER,
    report            JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON runs (tenant_id, hostname, run_date DESC);
```

Every run is stored — no overwrite of previous runs.

## Consequences

**Good:**
- Fleet Grid queries are fast indexed SQL — no JSON path expressions across thousands of rows.
- Full Run Report is available for drill-down without a second storage system.
- Historical data is preserved — trend analysis and Phase 2 delta reporting are possible without re-running the fleet.
- New JSONB fields are automatically available for future drill-down queries.

**Bad:**
- Extracted columns must stay in sync with the Run Report JSON field names. If ShellKnight renames `security_score`, the ingest endpoint must be updated.
- Storing every run means unbounded row growth. Acceptable at MSP fleet scale for the foreseeable future — add a retention policy if needed later.

## Alternatives considered

### Full JSONB only

All fields stored in JSONB, Fleet Grid queries use JSON path expressions. Rejected — JSON path scans across thousands of rows without extracted indexes are slow and will degrade as the fleet grows.

### Fully normalized schema

All report fields extracted into typed columns. Rejected — ShellKnight's report schema evolves rapidly. A fully normalized schema would require a migration every time a new field is added.
