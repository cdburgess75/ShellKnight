# 0006 — Stable device identity and movable site assignment

**Status:** Accepted

**Date:** 2026-07-03

## Context

Battlefield's first data model identified a machine by `hostname + the tenant of whichever API key POSTed the run`. Three problems surfaced quickly:

1. **Hostnames aren't unique** — `DESKTOP-XXXXXXX` collides across sites, and machines get renamed.
2. **Site was implicit in the API key** — the only way a machine "belonged" to a customer was that the Datto component carried that customer's key. There was no way to say "this device is at site X" independently, and no way to move it.
3. **No stable identity** — a rename created a "new" machine and orphaned its history.

We want a machine to have one identity for its whole life, and we want the flexibility to move a device between customers/sites (re-provisioned hardware, an MSP shuffling equipment) without losing history or re-keying it in the RMM.

## Decision

**Identity:** ShellKnight emits a stable `device_id` in its report — the hardware UUID (`Win32_ComputerSystemProduct.UUID`, survives OS reinstall and rename), falling back to the registry `MachineGuid`, then `host:<name>`. Battlefield keys devices on this value.

**Model:** a `devices` table holds identity (`device_id`, `hostname`, `datto_uid`) and a **mutable `tenant_id`** (the site). `runs` link to a device. Moving a device between sites is a single update to `devices.tenant_id`; all history stays attached to the device.

**Assignment — manual-wins:** the reporting API key sets a device's site **only on first sight**. After that, an operator's assignment in the dashboard is authoritative and is **not** overwritten by subsequent reports, even if the device keeps reporting under a different site's key. This is what makes "move" actually stick.

## Consequences

**Good:**
- A machine keeps one identity and its full history across renames.
- Devices are freely movable between sites from the dashboard, decoupled from which key they report with.
- Sets up real multi-tenancy: each customer is a tenant with its own key; a device's displayed site is authoritative regardless of key.
- New sites can be created on the fly during a move.

**Bad:**
- Manual-wins means a device can display a site that disagrees with the key it reports under. That's intentional but can look odd ("why is this box reporting with St. Michael's key but shown under Clinic B?"). The device_id + key are both visible for auditing.
- Hardware UUID is blank or duplicated on some cheap/whitebox hardware — the MachineGuid fallback covers most of it, but a truly duplicated UUID would merge two machines. Rare; can be detected by hostname mismatch on a device_id.
- Imaging/sysprep regenerates MachineGuid (not the hardware UUID) — for hardware-UUID machines this is a non-issue; for fallback machines a re-image looks like a new device.
- Migration created interim `host:<name>` device rows; the first report from ShellKnight ≥ v2026.07.03.014 (real hardware UUID) creates the canonical device, leaving the `host:` row stale until pruned.

## Alternatives considered

### Keep hostname + key as identity

Rejected. Not unique, not stable across rename, and site can't be changed without re-keying in the RMM.

### Key-always-wins for site assignment

Rejected. Simpler, but a device could never be persistently moved — the next report would drag it back to the key's site. Defeats the flexibility requirement.

### Use the Datto device UID as the primary identity

Rejected as primary (kept as a cross-reference). It's stable, but it ties Battlefield's core identity to the RMM; a device not yet in Datto, or a future non-Datto ingest path, would have no identity. A ShellKnight-emitted hardware ID keeps identity self-contained in the report.
