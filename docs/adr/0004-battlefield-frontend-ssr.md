# 0004 — Battlefield v0.1 uses server-side rendering (Jinja2), not a SPA

**Status:** Accepted

**Date:** 2026-05-25

## Context

Battlefield v0.1 needs a web UI for the Fleet Grid and drill-down views. A frontend architecture decision was needed: server-side rendered HTML (FastAPI + Jinja2 templates) or a JavaScript SPA (React/Vue) calling a JSON API backend.

## Decision

Use Jinja2 server-side rendering for Battlefield v0.1. FastAPI renders HTML templates directly. No separate frontend build pipeline, no JavaScript framework.

## Consequences

**Good:**
- No build pipeline — no npm, no webpack, no separate deployment step.
- One Python process serves the entire application — simpler hosting and ops.
- No CORS configuration needed.
- Faster to build for a single-user internal tool.
- Dashboard auth handled entirely by nginx basic auth — no session management in the app.

**Bad:**
- Not trivially convertible to a public API if Battlefield ever needs to serve external consumers (other frontends, mobile, third-party integrations).
- Page navigation requires full reloads — acceptable for an internal ops dashboard, not acceptable for a real-time console.

## Alternatives considered

### React or Vue SPA

A JavaScript SPA calling FastAPI JSON endpoints. Rejected for v0.1 — introduces a build pipeline, separate deployment, CORS configuration, and session/token auth complexity. Appropriate when there are multiple frontend consumers or when interactivity demands it. Neither applies at Phase 1.
