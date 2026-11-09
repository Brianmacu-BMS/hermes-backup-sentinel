# Provenance and scope

Backup Sentinel is an extraction and generalization of the Argus backup-checker use case jointly developed for Brianmacu-BMS's personal infrastructure. It is not derived from a listed community Hermes plugin.

The preserved source baseline used as a design reference has SHA-256:
`e47bd8e94df7133a4a1b378a1e9e1bc1fdfdf817d6b2325930e318d410911a96`.

The standalone source was generalized into policy-driven selection, a resource-bounded subprocess worker, and native Hermes public-context integration. The original deployed script is not a runtime dependency. No production archives, databases, credentials, private photos, tenant data, or operational logs belong in this distribution.

All test archives and databases are generated during tests from synthetic data, not checked into the plugin. The release payload contains reviewable source only.

Related existing products are acknowledged in README: BackupDrill has genuine backup-checksum and restoration verification for Supabase/Postgres; this plugin's initial scope is offline auditing of existing local gzip-compressed tar archives and explicitly selected SQLite snapshots. It does not claim to be the first backup verifier.
