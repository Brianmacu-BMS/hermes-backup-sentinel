"""Native public API registrations. Import has no filesystem/execution side effect."""
import json
from pathlib import Path
import shlex

VERSION = '0.1.0'
SCHEMA = {'name': 'backup_sentinel_audit', 'description': (
    'Audit an explicitly selected local tar.gz backup under operator-configured roots. '
    'Checks archive freshness/structure and configured SQLite members, never restores or repairs. '
    'Uses the host terminal approval path; only the target is model-controlled.'),
    'parameters': {'type': 'object', 'properties': {'target': {'type': 'string',
        'description': 'Explicit archive or directory; relative paths use this session cwd.'}},
        'required': ['target'], 'additionalProperties': False}}


def handle(ctx, args, **kwargs):
    try:
        from .backup_sentinel.integration import failure, read_operator_config, run_standalone_audit
        if type(args) is not dict or set(args) != {'target'}:
            return json.dumps(failure('invalid_tool_arguments'))
        return json.dumps(run_standalone_audit(ctx, read_operator_config(ctx), args['target']), sort_keys=True)
    except Exception:
        return json.dumps({'status': 'ERROR', 'reason': 'audit_dispatch_failed'})


def slash(raw, ctx=None):
    try:
        tokens = shlex.split(raw)
        if len(tokens) != 1 or tokens[0].startswith('-') or ctx is None:
            raise ValueError('target_required')
        return handle(ctx, {'target': tokens[0]})
    except Exception:
        return 'Usage: /backup-sentinel <quoted-target-path>. Policy is operator-configured; no overrides.'


def cli_handler(args):
    from .backup_sentinel.cli import run
    raise SystemExit(run(args))


def _cli_setup(parser):
    from .backup_sentinel.cli import parser_setup
    return parser_setup(parser)


def register(ctx):
    ctx.register_tool(name='backup_sentinel_audit', toolset='backup_sentinel', schema=SCHEMA,
        handler=lambda args, **kwargs: handle(ctx, args, **kwargs))
    ctx.register_command(name='backup-sentinel', handler=lambda raw: slash(raw, ctx),
        description='Audit an explicit local tar.gz backup through normal terminal approvals', args_hint='<quoted-target-path>')
    ctx.register_cli_command(name='backup-sentinel', help='Audit existing local tar.gz backups (no restore)',
        setup_fn=_cli_setup, handler_fn=cli_handler)
    ctx.register_skill('audit-backups', Path(__file__).parent / 'skills/audit-backups/SKILL.md')
