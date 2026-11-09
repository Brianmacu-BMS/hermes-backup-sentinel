# Security and trust boundary

Backup Sentinel audits explicitly chosen local `.tar.gz` backups. It does not prove that an application will restore or that an archive is authentic.

## What is trusted

- The installed Python runtime, operating system and plugin source.
- Operator-selected policy, approved target roots and private scratch root.
- Parent directories controlled by the operator, not hostile same-UID writers.
- Hermes's own terminal approval and execution context for model/slash invocations.

Native target/root policy is not a general filesystem sandbox. The standalone CLI is an operator command; it has no model-facing allowlist and relies on its explicit invocation scope. Linux is the initial supported platform; no untested cross-platform promises.

## What is untrusted

Archive headers, names, lengths, compressed data, database bytes and outcomes supplied by an outside producer. Required member names do not authenticate those files. Untrusted content is never executed as Python, shell or SQL scripts. SQLite's own integrity-check machinery still parses database bytes; keep the runtime patched and preserve process resource limits.

## Defenses and limits

- Explicit date-named selection; malformed/future matching candidates cannot cause silent fallback to an older passing archive.
- Bounded input, decompression, metadata/member counts, database materialization and wall runtime.
- No generic tar extraction or link following. Only approved ordinary SQLite members are copied under private per-invocation scratch.
- Credential-store filenames are not valid database-copy targets. No auth refresh, credential lookup or environment-file sourcing.
- Read-only immutable SQLite checks, generic machine-readable findings, no rows/raw exceptions/link targets.
- Fixed isolated Python worker, no shell or arbitrary executable, minimal environment, parent cleanup after ordinary failure/timeout.
- Metadata mutation detection is opportunistic, not an adversarial snapshot or cryptographic authenticity guarantee. Lexical symlink checks do not prevent all same-UID replacement races.

Full stream checking reads compressed/decompressed archive bytes even for members that are never parsed or exposed. Archive material can contain private data; get authorization before a real audit. A private temporary file is not encryption or secure deletion. Host termination/power loss can leave scratch remnants. Do not promise crash cleanup or secure erasure.

Any resource-policy refusal means coverage is incomplete. The software must not reinterpret LIMIT, TIMEOUT, unknown/unrun checks, cleanup failure or missing transport results as success.

## Reporting

Do not put real backup files, database rows, credentials, private logs or secret-bearing paths in a public issue. Describe a failure using a newly generated synthetic reproducer and the generic report. Source-only build acceptance is not a production security audit.
