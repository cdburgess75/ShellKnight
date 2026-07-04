# 0007 — Self-scheduling via Windows Scheduled Task (no agent, no RMM dependency)

**Status:** Accepted

**Date:** 2026-07-03

## Context

ShellKnight needs to run on a cadence, not just on demand. Fortress AI's charter is to *replace* Datto RMM/EDR, so building the schedule on a Datto policy is self-defeating — you cannot displace the thing you depend on. Two hard constraints stand:

1. **No agent installer** — no resident service or installed software on the endpoint.
2. **No ongoing RMM dependency** — Datto may be used to bootstrap, but not for steady-state operation.

Something must still *trigger* ShellKnight periodically. The only options are an RMM schedule (rejected), a persistent agent (rejected), or a native OS scheduler.

## Decision

ShellKnight schedules itself via a **Windows Scheduled Task**, which is native OS configuration — not installed software, not a resident process, nothing to patch.

- On every run, ShellKnight **ensures its own Scheduled Task exists** ("ShellKnight", runs as SYSTEM), recreating/updating it so the schedule never drifts. The tool is self-perpetuating: run it once and it keeps itself running.
- Cadence is **every 8 hours** with **per-device jitter** (offset derived from the device_id) so the fleet doesn't stampede Battlefield at the same instant.
- The task action is the standard one-liner: force TLS 1.2, download the latest `ShellKnight.ps1`, run it. So each scheduled run is always the current version — updates are automatic.
- Because scheduled runs have no Datto and no injected env vars, ShellKnight persists its settings (Battlefield URL, API key, cadence) to `C:\ProgramData\ShellKnight\config.json` on the bootstrap run and reads it on every run thereafter. **This local config is what severs the Datto dependency.**

Bootstrap (placing the first task) is a **one-time Datto push** (see the deployment note); after that first run the task is self-sustaining and Datto is never touched again.

## Consequences

**Good:**
- Fully agentless *and* free of any steady-state RMM dependency — aligned with the replace-Datto charter.
- Self-healing schedule; automatic version currency (each run pulls latest).
- Jitter spreads fleet load.
- One-time bootstrap can later move from Datto to GPO/Intune without changing the endpoint model.

**Bad:**
- Cadence bounds how fast queued remediation applies (see ADR 0008) — 8h worst case.
- Scheduled Task can be disabled/deleted locally; ShellKnight recreates it on any run, but a box that never runs again won't self-heal (covered by Battlefield staleness detection).
- `config.json` holds the tenant API key in plaintext on the endpoint (SYSTEM-readable). Acceptable for a tenant-scoped ingest key; documented for rotation.

## Alternatives considered

- **Datto scheduled policy** — rejected; steady-state dependency on the product being replaced.
- **Persistent agent/service (Squire)** — rejected; violates the no-agent thesis. Deferred indefinitely.
- **GPO/Intune-delivered scheduled task** — viable and preferred long-term for bootstrap; not required for the self-perpetuation mechanism itself. Left as a bootstrap option.
