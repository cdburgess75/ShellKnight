# 0005 — Battlefield triggers remediation via RMM (brokered reverse channel)

**Status:** Accepted

**Date:** 2026-07-03

## Context

[ADR 0001](0001-push-only-integration.md) established that Battlefield Phase 1 is strictly push-only: endpoints POST Run Reports, Battlefield displays them, nothing flows back. A true reverse channel (Battlefield → endpoint) was deferred to Phase 3, because it implied a persistent endpoint agent (Squire) listening for inbound commands.

Once Battlefield was live and ingesting fleet data, an operational need appeared immediately: seeing that 30 machines are on an old ShellKnight version, or that a box has a NetBIOS finding, is only half the job. The operator then has to leave the dashboard, open Datto RMM, find the device, and run the component — for every box. The dashboard could *see* the problem but not *act* on it.

The endpoints are already managed by Datto RMM, which has its own established, secured command channel (agent checks in, pulls its job, runs it, exits). ShellKnight is deployed and re-run through that channel today.

## Decision

Battlefield may trigger actions on endpoints, but only by **brokering through Datto RMM** — never by talking to the endpoint directly.

When an operator clicks Update / Fix NetBIOS / Schedule Reboot in the dashboard, Battlefield authenticates to the Datto API and fires the ShellKnight component (a quickjob) against that device, passing job variables (`SK_DISABLE_NETBIOS`, `SK_SCHEDULE_REBOOT_AT`, `SK_ABORT_REBOOT`, etc.). ShellKnight reads those as environment variables on its next run and acts accordingly.

The endpoint's model is unchanged: it still just pulls and runs a job from its RMM as it always has. No listener, no persistent agent, no inbound connection to the endpoint. The "reverse channel" exists only between Battlefield and the RMM's API.

## Consequences

**Good:**
- Closes the see-it/fix-it gap — remediation happens from the same screen as detection.
- No endpoint-side agent required; ShellKnight stays stateless run-and-exit. Squire (Phase 3) is still not needed.
- Reuses Datto's authenticated, audited, firewall-friendly command path rather than opening a new one.
- Remediation logic lives in ShellKnight (versioned, CI-checked, in git), driven by simple env-var switches — no logic on the dashboard side.
- Actions are gated behind the dashboard's basic-auth and are POST-only.

**Bad:**
- Departs from ADR 0001's "strictly push-only" stance. Battlefield is no longer a pure read-only viewer; it is now an actor.
- Couples Battlefield to the Datto RMM API (auth, rate limits, the no-stdout-via-API quirk). If the RMM changes, remediation breaks.
- Datto API credentials now live on the Battlefield server (auto2). That server's compromise would expose fleet-wide job-execution ability — mitigated by the auto2 hardening (key-only SSH, nginx lockdown, fail2ban) but a real increase in blast radius.
- Actions are fire-and-confirm-later: the quickjob is queued instantly, but the effect only lands when the box next checks in. The UI reflects Datto job status, not endpoint truth.

## Alternatives considered

### Stay pure push-only (ADR 0001 unchanged)

Rejected. The operational cost of context-switching to RMM for every action was high enough that the dashboard's value was materially reduced. The brokered approach adds the capability without adding an endpoint agent.

### Direct Battlefield → endpoint channel

Rejected, same reasoning as ADR 0001: requires a listener on every endpoint (firewall/NAT/attack-surface cost) and is Squire/Phase 3 scope. Brokering through the RMM gets the outcome with none of that.

### Bake remediation logic into Battlefield (run PowerShell against the box itself)

Rejected. Battlefield would need its own remote-execution path to endpoints (WinRM/SSH/etc.), duplicating what the RMM already does securely. Keeping the logic in ShellKnight and only *triggering* it via RMM keeps one source of truth for what runs on an endpoint.
