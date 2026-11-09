---
name: audit-backups
description: Audit explicitly approved local backup archives.
version: 0.1.0
author: Brianmacu-BMS
license: MIT
---

# Audit local backups

Use when the user asks to check an existing local backup's freshness, archive integrity, required members, or archived SQLite database health.

## Procedure

1. Obtain scope for the actual backup location. Real backup archives can contain credentials and private conversations. A plugin installation is not blanket permission to inspect every mounted backup.
2. Use `backup_sentinel_audit` only for an explicit target beneath operator-configured allowed roots. Do not change that configuration, widen limits, discover new mounts, or bypass a refusal with terminal commands.
3. Report the actual structured status and check coverage. LIMIT means the policy budget prevented full checking, not proven corruption. ERROR/TIMEOUT/not_run are not passes. A recent job status is not independent archive validation.
4. The default policy checks `.hermes/state.db` in an archive named `backup-YYYYMMDD.tar.gz`. Different layouts need an operator-selected policy. Native Hermes ZIP archives are not supported by version 0.1.0.
5. Explain that the source archive is not modified, but explicitly selected SQLite snapshots are copied into private temporary scratch and removed afterward. Never request materialization of credential stores or expose archive contents, rows, link targets, or raw SQLite errors.
6. A successful integrity audit does not prove restoration, application health, source authenticity, off-host redundancy, or ransomware resistance. Do not say a backup is recoverable unless a separate restore drill actually established it.
7. No automatic repair, backup creation, deletion, retention, restoration, scheduling, network access, model call, or credential management is part of this plugin.
