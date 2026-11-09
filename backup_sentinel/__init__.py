"""Backup Sentinel: stdlib-only local .tar.gz backup audit engine (v0.1.0).

Public API (see PLAN.md):

    from backup_sentinel.model import AuditPolicy
    from backup_sentinel.supervisor import run_audit
    report = run_audit(target='/absolute/file-or-directory', policy=policy,
                       scratch_root='/absolute/existing/private-scratch',
                       now='YYYY-MM-DD')

Standard library only, Python >= 3.11, Linux.  No restore claim is made.
"""

VERSION = "0.1.0"

__all__ = ["VERSION"]