# 0009: Customer-facing security score

**Status:** Accepted

**Date:** 2026-09-17

## Context

ParaTech pays Fortra per customer for Frontline VM, whose customer-visible deliverable is a
three-page "Vulnerability Assessment Executive Summary". The September 2026 issue for one
customer contains, in full:

- a cover page (scan name, scan policy, dates, prepared-for, business group, rating method)
- one plain-language sentence of asset and vulnerability counts
- **Security GPA 3.19 (B+)** on a 0 to 4 scale
- a pie of asset ratings and a bar of vulnerability counts by severity
- two twelve-month trend charts (GPA over time, severity counts over time)

It contains no findings, no remediation advice, and no hostnames. It is a scorecard, not an
assessment. Its entire product is one number and its movement over time.

Notably, that customer scores B+ with **zero** critical, high, or medium vulnerabilities:
eleven low and seventeen trivial occurrences across nine assets. The GPA is therefore not a
count of findings. It is weighted by per-asset rating and assigned business risk, using a
methodology Fortra does not publish.

Fortress AI already collects richer internal data than Frontline sees, and vPen covers the
external side. What we lack is the product layer: a single defensible number, a roll-up, and
a trend.

The scores we do have have each been publicly wrong once:

- ShellKnight's per-device security grade marked the **entire fleet F for two months**, because
  Microsoft Defender was excluded from the AV product list and never credited back.
- vPen graded an external scan **A** when every UDP port returned `open|filtered`, which is the
  signature of a scan that learned nothing.

Both failures share a cause: a *detection* or a *collection failure* was allowed to move a
*risk* score. Any number we put in front of a cyber insurer or a client security
questionnaire has to be immune to that.

## Decision

**One tenant-level Security Score.** Held internally as 0 to 100, published to the customer as a
letter grade plus a 0.0 to 4.0 GPA, so it reads the way the Fortra report the customer already
knows reads.

**Scored from `VULN`-class findings only.** `bf/findings.py` classifies every finding as `VULN`,
`DETECTION`, or `OPERATIONAL`. Only `VULN` moves the score. A detection that turns out to be
ParaTech's own support tooling, or an antivirus probe that fails to run, cannot change a grade.
This is the structural fix for both historical failures.

**Tenant score is a criticality-weighted mean of device scores,** not a flat average.

| Tier | Weight | Source |
|---|---|---|
| Critical | 3 | operator-set only, until `domain_role` is added to the Run Report |
| Important | 2 | auto-derived: `hardware_type == 'Server'` |
| Standard | 1 | auto-derived: everything else |

**Criticality follows manual-wins.** Battlefield derives a default tier from the Run Report on
ingest; an operator may override it per device; the override is sticky and no later report
overwrites it. This is the same rule [ADR 0006](0006-device-identity-and-site-assignment.md)
already applies to site assignment, so criticality behaves the way operators expect site to.

**The methodology is published** as an appendix to the customer report.

## Consequences

**Good:**

- Retires a per-customer Fortra subscription for a deliverable we can generate from data we
  already hold.
- The score survives a false positive. Detections and operational items are reported but never
  scored, so the two ways we have already been wrong cannot recur.
- Criticality is derived server-side from fields the Run Report already carries, so it applies
  retroactively to stored runs. `runs.report` is JSONB, so there is no migration and no re-scan.
- Publishing the methodology is a direct advantage over Fortra, whose GPA is opaque. A customer
  can see what moves the number, and so can their insurer.
- A weighted mean states the thing an MSP actually believes: a patch gap on a domain controller
  is not the same event as the same gap on a laptop.

**Bad:**

- Two scales for one number (0 to 100 internal, 0.0 to 4.0 published) is a translation that must
  be kept consistent in code and in the report template, or the two will drift.
- Weighting is a judgement, and a published methodology invites argument about the weights. That
  is the correct trade against an opaque number, but it is a real support burden.
- Tier `Critical` cannot be auto-derived today. Until `domain_role` is added to the Run Report,
  every domain controller must be flagged by hand, and an unflagged one is silently under-weighted.
- Excluding `DETECTION` from the score means a genuine compromise indicator does not lower the
  grade. Detections must stay prominent in the report body so this reads as a deliberate
  separation and not as an omission.

## Alternatives considered

### Keep paying Fortra and build only the technical report

Rejected. This was a real option: build the per-finding detail Fortra does not provide and let
Frontline keep supplying the scorecard. It was rejected because the scorecard is the document
management actually reads, and leaving it with a vendor leaves the customer relationship with
that vendor. The trend line is the retention argument.

### Flat average of device scores

Rejected. It lets a fleet of healthy laptops hide a neglected domain controller, which is the
exact inversion of how risk works. It is also what makes a score easy to argue with.

### Score everything, including detections and operational items

Rejected. This is what we did, and it produced a fleet-wide F from one antivirus bug and an
inflated IOC count from ParaTech's own ScreenConnect instances. A score that a false positive
can move is not defensible to a third party.

### Adopt Fortra's 0 to 4 GPA as the only scale

Rejected. A 0 to 4 scale is the right thing to *show* a customer because it is familiar, but it
is too coarse to compute with. Holding 0 to 100 internally keeps per-finding deductions legible
and keeps the letter bands adjustable without rescoring history.
