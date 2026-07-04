# 0008 — Remediation via pull-queue on check-in (no push, no RMM)

**Status:** Accepted

**Date:** 2026-07-03

## Context

[ADR 0005](0005-battlefield-remediation-via-rmm.md) implemented on-demand remediation (Update, Fix NetBIOS, Schedule/Cancel Reboot) by having Battlefield fire a Datto quickjob — a push through the RMM. That works but keeps a steady-state Datto dependency, which conflicts with the replace-Datto charter and with [ADR 0007](0007-self-scheduling-no-agent.md) (no RMM in steady state).

We need Battlefield to still trigger endpoint actions, without pushing and without an agent listening for inbound commands.

## Decision

Flip the channel from **push** to **pull**. The endpoint's own scheduled check-in fetches and applies queued work.

- Dashboard actions **enqueue** into a `commands` table (device, action, params, status) — they do **not** contact the endpoint.
- ShellKnight's report POST **is** the check-in. Battlefield's response to `/api/v1/runs` includes that device's queued commands. ShellKnight executes them at end of run (disable NetBIOS, schedule/cancel reboot, …) and they are marked delivered/done.
- No inbound connection to the endpoint, no listener, no persistent agent. The only network flow is the endpoint calling out to Battlefield — same as the report POST already does.

Consequence by design: actions apply on the **next check-in**, bounded by the ADR 0007 cadence (8h). The UI shows "queued — applies next check-in" rather than implying instant execution.

## Consequences

**Good:**
- Removes Datto from remediation entirely; the report POST does double duty as check-in + command fetch (one round trip).
- Same minimal, outbound-only security posture as ingest — nothing new exposed on the endpoint.
- Commands are auditable rows (who queued what, when delivered) — better than fire-and-forget quickjobs.
- The "Update" action becomes largely moot: every scheduled run already pulls the latest ShellKnight, so version currency is automatic.

**Bad:**
- Not instant — worst-case latency equals the cadence (8h). Genuine incidents needing faster action require tightening cadence or a future priority check-in, not a return to push.
- A command queued for a device that stops checking in never applies (surfaced by staleness detection).
- Battlefield must reconcile command state (queued → delivered → done) and handle re-delivery/idempotency if a run dies mid-execution.

## Alternatives considered

- **Keep Datto push (ADR 0005)** — rejected for steady state; retained only as a legacy fallback flag until the pull model is proven, then removed.
- **Short heartbeat (~15 min) for near-instant pull** — rejected for now; a frequent scheduled task starts to resemble an agent. Revisit if incident latency demands it.
- **Direct inbound channel (WinRM/SSH) from Battlefield** — rejected; requires reachability/credentials to every endpoint across NAT and a listening surface. This is exactly what the pull model avoids.
