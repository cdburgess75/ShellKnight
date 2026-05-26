# 0002 — POST the existing Run Report JSON unchanged to Battlefield

**Status:** Accepted

**Date:** 2026-05-25

## Context

ShellKnight already produces a JSON Run Report written to disk at run-end. When adding Battlefield integration, a decision was needed: send that same JSON as the POST payload, or define a separate trimmed schema for the API.

## Decision

ShellKnight POSTs the exact same JSON document it writes to disk — no transformation, no separate schema. Battlefield stores the full document in a `report JSONB` column alongside a small set of extracted indexed columns (see ADR-0003).

## Consequences

**Good:**
- Zero additional code in ShellKnight — the payload is already constructed before the POST.
- Single source of truth: disk file and Battlefield database always contain the same data.
- New fields added to ShellKnight automatically flow to Battlefield with no schema changes on either side.
- JSONB storage in PostgreSQL supports querying any field without a predefined schema.

**Bad:**
- Battlefield receives verbose fields it may never query (log-level detail, internal counters). Accepted — storage cost is negligible at MSP fleet scale.
- No API versioning contract between ShellKnight and Battlefield — if the JSON structure changes significantly, both sides must be updated together.

## Alternatives considered

### Trimmed API schema

A separate, minimal payload (hostname, scores, IOC count, key findings only). Rejected because it requires maintaining two schemas in sync — every new ShellKnight field must be explicitly added to the API schema or it is silently lost. The maintenance cost exceeds any payload size savings at this scale.
