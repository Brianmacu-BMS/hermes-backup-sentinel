"""Standalone audit command; imports work both as a package and isolated script."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from backup_sentinel.model import AuditPolicy
    from backup_sentinel.supervisor import run_audit, _error_report
    from backup_sentinel.reports import EXIT_CODES, unique_object
else:
    from .model import AuditPolicy
    from .supervisor import run_audit, _error_report
    from .reports import EXIT_CODES, unique_object


def parser_setup(parser):
    parser.add_argument('--version', action='version', version='Backup Sentinel 0.1.0')
    parser.add_argument('target', help='explicit archive/directory; PREFIXYYYYMMDD.tar.gz')
    parser.add_argument('--scratch-dir', required=True, help='existing private scratch directory outside backups')
    parser.add_argument('--prefix', default='backup-', help='literal filename prefix')
    parser.add_argument('--required', action='extend', nargs='+', metavar='MEMBER')
    parser.add_argument('--sqlite', action='extend', nargs='+', metavar='MEMBER')
    parser.add_argument('--archive-only', action='store_true', help='explicitly skip application/SQLite checks')
    parser.add_argument('--policy-json', help='explicit required_members/sqlite_members lists (no file read)')
    parser.add_argument('--now', help='deterministic date override YYYY-MM-DD (CLI only)')
    parser.add_argument('--json', action='store_true', help='structured report')
    for name in ('max-age-days', 'max-compressed-bytes', 'max-uncompressed-bytes', 'max-db-bytes', 'max-members', 'timeout-seconds'):
        parser.add_argument('--' + name, type=int)
    return parser


def build_parser():
    return parser_setup(argparse.ArgumentParser(description='Audit existing local tar.gz backups. Does not prove restoration.'))


def _members(args):
    if args.policy_json is not None:
        if len(args.policy_json.encode('utf-8')) > 32768 or args.required is not None or args.sqlite is not None or args.archive_only:
            raise ValueError('invalid_member_policy')
        value = json.loads(args.policy_json, object_pairs_hook=unique_object)
        if type(value) is not dict or set(value) != {'required_members', 'sqlite_members'}:
            raise ValueError('invalid_member_policy')
        return value['required_members'], value['sqlite_members']
    if args.archive_only:
        if args.required is not None or args.sqlite is not None:raise ValueError('conflicting_policy')
        return [], []
    return (args.required if args.required is not None else ['.hermes/state.db'],
        args.sqlite if args.sqlite is not None else ['.hermes/state.db'])


def run(args):
    try:
        required, sqlite = _members(args)
        values = {'prefix': args.prefix, 'required_members': required, 'sqlite_members': sqlite}
        for name in ('max_age_days', 'max_compressed_bytes', 'max_uncompressed_bytes', 'max_db_bytes', 'max_members', 'timeout_seconds'):
            value = getattr(args, name)
            if value is not None:values[name] = value
        policy = AuditPolicy(**values)
        target = str(Path.cwd() / args.target) if not Path(args.target).is_absolute() else args.target
        scratch = str(Path.cwd() / args.scratch_dir) if not Path(args.scratch_dir).is_absolute() else args.scratch_dir
        report = run_audit(target=target, policy=policy, scratch_root=scratch, now=args.now)
    except (ValueError, TypeError, OSError, OverflowError, RecursionError):
        report = _error_report('invalid_policy_or_request')
    if args.json:
        print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    else:
        print('Backup Sentinel: ' + report['status'])
        print('Reason: ' + report['reason'])
        for name, status in report['checks'].items():print('  ' + name + ': ' + status)
        print('Scratch cleaned: ' + str(report['scratch_cleaned']).lower())
        print('Restore tested: false — integrity validation is not a restore drill.')
    return EXIT_CODES[report['status']]


def main(argv=None):
    return run(build_parser().parse_args(argv))

if __name__ == '__main__':raise SystemExit(main())
