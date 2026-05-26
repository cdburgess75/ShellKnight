# 0001 — Battlefield Phase 1 is push-only (no reverse channel)

**Status:** Accepted

**Date:** 2026-05-25

## Context

Phase 1 of Fortress AI requires ShellKnight and Battlefield to be connected. The question was whether Battlefield should only receive data from endpoints, or also be able to send commands back (trigger scans, push config, etc.). ShellKnight currently has no persistent process on the endpoint — it runs on demand via RMM and exits.

## Decision

Phase 1 is strictly one-directional: ShellKnight pushes Run Reports to Battlefield at run-end. Battlefield receives and displays. No commands flow from Battlefield to endpoints in Phase 1.

## Consequences

**Good:**
- No persistent agent required on the endpoint — ShellKnight remains a stateless, run-and-exit script.
- Battlefield v0.1 can be a read-only dashboard with a simple ingest endpoint — no command queue, no connection state, no endpoint-side listener.
- Dramatically reduces Phase 1 scope and time to a working dashboard.
- Security surface is minimal — endpoints call out to Battlefield, not the reverse.

**Bad:**
- Cannot trigger a ShellKnight run from the dashboard — must still use RMM or manual execution.
- Cannot push config changes to endpoints from Battlefield — config is still per-script at deployment time.

## Alternatives considered

### Two-way channel from Phase 1

Rejected. Requires a persistent agent on every endpoint to receive inbound commands. That agent is Squire, which is Phase 3. Building it in Phase 1 doubles scope.

### Pull model (Battlefield polls endpoints)

Rejected. Requires endpoints to expose a listening service, which creates firewall/NAT complexity and a large attack surface on every managed machine. Push-from-endpoint is simpler and more secure.
