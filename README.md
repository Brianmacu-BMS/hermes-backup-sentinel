# Backup Sentinel

**Audit the backup you have—not just the job that said it succeeded.**

Backup Sentinel is a Linux-first, standard-library Python auditor for existing local gzip-compressed tar backups. It can run as a standalone CLI or through native Hermes tool/slash/CLI registrations.

**Version 0.1.0 is a source release, not a marketplace acceptance or deployment claim.** It is not installed in the development Hermes environment. Check the exact commit's CI for standalone and guarded, disposable GitHub-runner native acceptance; neither implies approval to activate it on a live profile. No paid-model route is involved in the auditor itself.

## What it checks

- Filename-date selection and freshness; a broken newest archive never quietly falls back to an older good one.
- Complete gzip stream integrity and bounded decompression.
- Tar structure, unsafe member paths, duplicate normalized names, special/sparse entries and required regular files.
- Explicitly selected archived SQLite snapshots with read-only integrity and foreign-key checks.
- Private scratch cleanup and source-file metadata stability during verification.

Selection is deliberately fail-closed: any matching date-shaped impossible/future candidate or matching symlink/nonregular entry blocks a directory audit, even if another regular archive exists. It is not silently ignored as an inconvenient older entry.

It does **not** create backups, restore an application, delete archives, change retention, schedule jobs, fix configuration, contact a network service, or manage credentials. A metadata-stability check is not a cryptographic authenticity guarantee.

## Initial supported scope

- Linux, Python 3.11 or newer. Runtime dependencies: standard library only.
- `.tar.gz` archives named `PREFIXYYYYMMDD.tar.gz` (default `backup-20261108.tar.gz`). Dates come from names, not modification times.
- Default application policy requires and checks `.hermes/state.db`. Configure another explicit layout or select archive-only checking.
- **Native Hermes ZIP backups are not supported in 0.1.0.** Other compression formats, encrypted archives, remote buckets and restore drills are not silently treated as supported.
- Trusted parent directories are required. Path guards and resource limits are not a sandbox against malicious users replacing filesystem paths or malicious kernel/filesystem behavior.

## Standalone use—no plugin installation required

From the source directory, with an existing private scratch directory outside the backup tree:

```sh
python -B -m backup_sentinel /srv/backups --scratch-dir /home/me/private-scratch --json
```

That directory must contain date-named archives. To audit a single archive:

```sh
python -B -m backup_sentinel /srv/backups/backup-20261108.tar.gz   --scratch-dir /home/me/private-scratch --json
```

Different archive layout:

```sh
python -B -m backup_sentinel /srv/backups --prefix app-daily-   --required data/application.db --sqlite data/application.db   --scratch-dir /home/me/private-scratch --json
```

`--required` and `--sqlite` accept explicit member names and can be repeated. Credential-store names are never valid SQLite extraction targets. Nonrequired links may be inspected only as opaque metadata, never followed or materialized. Link targets do not establish restore safety.

For container checks with no application-specific requirements, explicitly use `--archive-only`; its report makes the narrower coverage visible. `--now YYYY-MM-DD` is a deterministic CLI/test override, not a model-controlled plugin parameter.

Resource-policy options are listed by `--help`: compressed/uncompressed bytes, SQLite bytes, member count, age and wall timeout. Limits are validated and capped; increasing one does not establish archive safety.

### Reports and exit status

JSON reports include status/reason, per-check results, coverage, selected date, cleanup outcome and `restore_tested: false`. Not-requested or unrun checks must not be described as passing.

Check fields can describe work completed before a later source-change or cleanup error. Only overall `status: OK` is success; individual `ok` checks never override an error.

| Status | Exit | Meaning |
|---|---:|---|
| `OK` | 0 | Requested checks passed within policy. |
| `MISSING` / `STALE` | 1 | No matching backup, or selected backup too old. |
| `INVALID` | 2 | Invalid archive, members or archived database. |
| `LIMIT` | 3 | Policy budget prevented complete checking; not proof of corruption. |
| `ERROR` | 4 | Invalid request/policy, environmental failure, source change or cleanup failure. |
| `TIMEOUT` | 5 | Audit exceeded its wall deadline. |

Argument syntax errors also use argparse's nonzero exit. Human reports are available by omitting `--json`.

## Hermes integration

The package declares one model tool, `backup_sentinel_audit`, plus `/backup-sentinel` and `hermes backup-sentinel` registrations. It bundles an operational skill and adds no hooks, middleware, model calls, automatic scans or schedules.

**Disabled-by-configuration behavior:** configure explicit allowed target roots and a private scratch path before using the model tool or slash command. The model supplies only a target; it cannot widen roots, change limits, alter credential access or choose an executable.

Illustrative plugin settings (not automatically applied):

```yaml
plugins:
  entries:
    backup-sentinel:
      settings:
        allowed_roots:
          - /srv/backups
        scratch_dir: /home/me/private-scratch
        prefix: backup-
        required_members:
          - .hermes/state.db
        sqlite_members:
          - .hermes/state.db
        max_age_days: 2
        max_compressed_bytes: 268435456
        max_uncompressed_bytes: 536870912
        max_db_bytes: 33554432
        max_members: 4096
        timeout_seconds: 30
```

Use the supported Hermes configuration interface after reviewing the actual paths/policy. Do not copy these placeholder paths blindly. Installing a plugin does not authorize reading every mounted backup.

Model/slash execution delegates the fixed local CLI through `ctx.dispatch_tool('terminal', ...)`, retaining Hermes's terminal approvals and refusal behavior. If the terminal backend cannot access the locally installed plugin path, the request must fail; this release does not copy code or archives into a remote execution backend. Native relative paths are session-relative; standalone paths follow CLI working-directory semantics.

Installation and activation are separate operator actions, never performed by an audit. Review the exact source pin and use supported Hermes installation tooling only with approval for the intended environment; do not enable it on a live profile just to inspect it. Native acceptance under `tests/native_installed_acceptance.py` refuses local and self-hosted execution before importing the SDK, and runs only in the isolated GitHub-hosted workflow.

## Privacy and security disclosure

- Reads explicitly selected local archives and directory metadata outside the plugin's own data directory. Full gzip verification necessarily streams archived bytes, including bytes of files whose contents are never parsed or returned.
- Does not acquire credentials from archived or live login/config stores. Required-file presence checks do not parse their contents. Only named, permitted SQLite members are materialized; never arbitrary archive extraction.
- Archived SQLite may contain private conversations. The tool never returns rows, raw database errors, member payloads, arbitrary link targets or private exception text, but operating-system access and temporary plaintext copies are still real disclosures.
- Starts a fixed Python worker with no shell and a minimal environment. Parent-owned private scratch is cleaned after normal completion or a timeout. Resource limits reduce risk but do not make hostile archives intrinsically safe.
- No plugin-owned network requests, telemetry, OAuth flows, credential changes or long-running background daemon.
- Native terminal commands, selected paths and structured results may appear in Hermes's ordinary tool transcript and therefore reach the configured conversation model. No additional inference is made by this plugin; calling it from an agent conversation still has that conversation's normal cost.
- An abrupt kill/power loss can prevent cleanup. Do not equate ordinary cleanup tests with crash-proof secure erasure. SSD/filesystem remnants are outside this product's guarantee.

See [SECURITY.md](SECURITY.md) for the trust boundary.

## Reproducible synthetic demo

Set `TMPDIR` to an existing private scratch location, then run:

```sh
python -B scripts/demo.py
```

The script creates only synthetic archives and a synthetic SQLite database. It exercises good data, a missing required file, a corrupt database, and a corrupt newest archive alongside an older valid archive. It retains an explicit JSON receipt in the newly created demo directory. It does not inspect any existing backup location.

The demo uses a fixed date override, so it remains reproducible instead of becoming stale next week.

## Tests and source packaging

```sh
sh scripts/run_tests.sh
PYTHON='python3' sh scripts/run_tests.sh
python -B scripts/build_release.py --output /path/outside/source/backup-sentinel-0.1.0.zip
```

Tests generate synthetic archives/databases in `TMPDIR`; none are production copies. Contract tests use a fake registration context, not a live Hermes loader. The packaging command refuses an existing destination, ships reviewable source only, adds a source hash manifest, and reopens/byte-verifies the ZIP. Native installed acceptance and catalog admission must not be inferred from standalone/fake-context tests.

## How this differs from related plugins

- [BackupDrill](https://hermes-agent.nousresearch.com/marketplace/backupdrill) verifies checksums and actually restores Supabase/Postgres snapshots into Docker. It provides restore evidence in its supported domain; Backup Sentinel does not.
- [S3](https://hermes-agent.nousresearch.com/marketplace/s3) provides object-storage backup transport and restoration.
- [Telegram Dashboard](https://hermes-agent.nousresearch.com/marketplace/telegram_dashboard_probe) displays a backup timer's reported status; Backup Sentinel independently reads the selected archive.
- [vt-check](https://hermes-agent.nousresearch.com/marketplace/vt-check) shares archive-safety concerns but targets download reputation/forensics, not backup-policy and SQLite health.

This is not a claim to be the first backup verifier. The niche is a bounded offline audit of already-existing local backups, with no cloud account or Docker requirement.

MIT licensed. See [PROVENANCE.md](PROVENANCE.md).
