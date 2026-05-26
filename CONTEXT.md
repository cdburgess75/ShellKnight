# Context: Fortress AI

Full-stack MSP platform authored by C. David Burgess, PTech LLC. Goal: replace Datto RMM + Datto EDR. Components are independently deployable and communicate through well-defined boundaries.

## Terms

### Fortress AI

The full platform name. Comprises multiple named components (ShellKnight, Battlefield, Squire, etc.). Not a single application — a family of tools designed to be deployed together or independently.

### ShellKnight

The endpoint security remediation engine. A single PowerShell script that runs headlessly on a Windows endpoint (via RMM or manually), executes 8 engines covering detection, hardening, cleanup, and reporting, then exits. It is NOT a persistent agent — it runs, produces a Run Report, and terminates.

### Battlefield

The central command-and-control dashboard for Fortress AI. A web application (FastAPI + Jinja2, PostgreSQL backend) that receives Run Reports from ShellKnight, stores them, and displays fleet health. In Phase 1, Battlefield is read-only — it receives data but does not send commands to endpoints.

### Tenant

A single MSP client. Each Tenant has its own API Key used to authenticate ShellKnight POST requests to Battlefield. Tenant data is namespaced in the database — one Tenant's Run Reports are never visible alongside another's.

**Example:** PTech LLC's client "Escla" is one Tenant. Their ShellKnight deployments all share the same API Key for Escla.

### Run

A single execution of ShellKnight on a single endpoint. A Run has a start time, a hostname, and produces exactly one Run Report. Runs are not re-runnable or resumable — each invocation is independent.

### Run Report

The JSON document produced at the end of every Run. Written to disk at `C:\ProgramData\ShellKnight\JSON\` and (when Battlefield integration is enabled) POSTed to the Battlefield ingest endpoint. The Run Report is the single source of truth for a Run — the log file is a human-readable companion, not the record of truth.

### Fleet Grid

The main view in the Battlefield dashboard. Displays one row per machine (latest Run per hostname), showing: hostname, tenant, last run date/time, security grade, performance grade, IOC alert count, and status (clean / action required). Clicking a row shows the full Run Report for that machine's last Run.

### API Key

A secret string assigned per Tenant. Included by ShellKnight in the `X-Api-Key` HTTP header on every POST to Battlefield. Battlefield uses it to identify the Tenant and store the Run Report in the correct namespace. NOT a per-machine or per-user credential — all endpoints belonging to the same Tenant share one API Key.

### Ingest Endpoint

The Battlefield FastAPI route that receives Run Reports from ShellKnight. Accepts POST requests with a JSON body (the Run Report) and an `X-Api-Key` header. Validates the key, extracts indexed fields, and writes to the `runs` table.

### Phase 1

The first milestone of Fortress AI development. Scope: ShellKnight POSTs Run Reports to Battlefield; Battlefield stores and displays them in the Fleet Grid. No reverse channel, no commands sent to endpoints, no persistent agent. Completion criteria: fleet data flowing into a live dashboard.
