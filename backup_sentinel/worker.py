"""Backup Sentinel audit worker: bounded request/result shim.

The supervisor launches this module as a standalone script under an
isolated interpreter (``-I -B``); the package root is added to ``sys.path``
explicitly because isolated mode strips both cwd and script directory.
The worker reads one small JSON request from stdin, runs the in-process
engine against synthetic-or-authorized data, and writes one small JSON
report to stdout.  It never touches the network, never runs shell commands,
and never inherits the parent environment (the supervisor passes a minimal
one).

Request (JSON object): {"target": str, "policy": {...}, "scratch": str,
"now": "YYYY-MM-DD" | null}.  Output: one JSON object (the report contract)
followed by a newline; exit code 0 whenever a report is emitted.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_sentinel import engine
from backup_sentinel.model import AuditPolicy

MAX_REQUEST_BYTES = 64 * 1024


def resource_limits(cpu_seconds=302):
    """Apply limits after exec, never through thread-unsafe preexec_fn."""
    import resource
    for kind, desired in ((resource.RLIMIT_AS, 512 * 1024**2),
                          (resource.RLIMIT_FSIZE, 256 * 1024**2),
                          (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64),
                          (resource.RLIMIT_CPU, cpu_seconds)):
        _, hard = resource.getrlimit(kind)
        bound = desired if hard == resource.RLIM_INFINITY else min(desired, hard)
        resource.setrlimit(kind, (bound, bound))


def build_report(status, reason, checks=None, coverage="archive_integrity_only",
                 selected_date=None, scratch_cleaned=False):
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "checks": checks or {"freshness": "not_run", "gzip": "not_run",
                             "tar": "not_run", "required": "not_run",
                             "sqlite": "not_run"},
        "coverage": coverage,
        "restore_tested": False,
        "scratch_cleaned": scratch_cleaned,
        "selected_date": selected_date,
    }


def _emit(report):
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    sys.stdout.flush()


def main():
    try:
        resource_limits()
    except (OSError, ValueError, ImportError):
        _emit(build_report("ERROR", "resource_limits_unavailable"))
        return 0
    data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        _emit(build_report("ERROR", "request_oversize"))
        return 0
    try:
        from backup_sentinel.reports import unique_object
        request = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
        if type(request) is not dict or set(request) != {"target", "policy", "scratch", "now"}:
            raise ValueError("request must be a JSON object")
    except (ValueError, UnicodeDecodeError):
        _emit(build_report("ERROR", "invalid_request"))
        return 0
    try:
        policy = AuditPolicy.from_mapping(request.get("policy"))
    except Exception:
        _emit(build_report("ERROR", "invalid_policy"))
        return 0
    target = request.get("target")
    scratch = request.get("scratch")
    now = request.get("now")
    if not isinstance(target, str) or not isinstance(scratch, str):
        _emit(build_report("ERROR", "invalid_request"))
        return 0
    try:
        report = engine.run_audit(target=target, policy=policy,
                                  scratch_root=scratch, now=now)
    except Exception:
        report = build_report("ERROR", "internal_error")
    _emit(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())