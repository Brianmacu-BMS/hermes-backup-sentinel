"""Approval-preserving native bridge to the fixed local standalone CLI."""
import json
from pathlib import Path
import shlex
import sys
from .paths import absolute_path, guard_path, private_scratch, separate_paths
from .reports import EXIT_CODES, load_report, unique_object
from .schemas import DEFAULTS, validate_policy_config


def failure(reason, status='ERROR'):
    return {'status': status, 'reason': reason, 'error': reason}


def read_operator_config(ctx):
    defaults = {**DEFAULTS, 'allowed_roots': [], 'scratch_dir': ''}
    return {name: ctx.get_config(name, value) for name, value in defaults.items()}


def resolve_native_path(target):
    if not isinstance(target, str) or not target:
        raise ValueError('invalid_target')
    path = Path(target)
    if not path.is_absolute():
        from agent.runtime_cwd import resolve_agent_cwd
        cwd = absolute_path(resolve_agent_cwd())
        path = cwd / path
    # Never resolve() or normpath() before alias/parent traversal checks.
    return absolute_path(str(path))


def safe_lexical_guard(path, allowed_roots):
    candidate = absolute_path(str(path))
    roots = [absolute_path(root) for root in allowed_roots]
    if not any(candidate.is_relative_to(root) for root in roots):
        raise PermissionError('target_outside_allowed_roots')
    for root in roots:
        if candidate.is_relative_to(root):
            guard_path(str(root))
            break
    return str(guard_path(str(candidate), missing_final=True))


def build_cli_command(target, scratch_dir, config):
    cli = Path(__file__).parent / 'cli.py'
    cmd = [sys.executable, '-I', '-B', str(cli), target, '--scratch-dir', scratch_dir,
        '--prefix=' + config['prefix'], '--json']
    if not config['required_members'] and not config['sqlite_members']:
        cmd.append('--archive-only')
    else:
        # Explicit empty lists must not silently restore the CLI's defaults.
        cmd.extend(['--policy-json', json.dumps({'required_members': config['required_members'],
            'sqlite_members': config['sqlite_members']}, separators=(',', ':'))])
    for name in ('max_age_days', 'max_compressed_bytes', 'max_uncompressed_bytes', 'max_db_bytes', 'max_members', 'timeout_seconds'):
        cmd.extend(['--' + name.replace('_', '-'), str(config[name])])
    return cmd


def validate_terminal_result(result):
    try:
        if isinstance(result, str):
            if len(result.encode('utf-8')) > 65536:
                raise ValueError('oversize_transport')
            result = json.loads(result, object_pairs_hook=unique_object)
        if type(result) is not dict or type(result.get('exit_code')) is not int:
            raise ValueError('invalid_transport')
        if result['exit_code'] == -1:
            return failure('approval_denied', 'DENIED')
        if result.get('error') or result['exit_code'] not in set(EXIT_CODES.values()):
            raise ValueError('terminal_failed')
        report = load_report(result.get('output'))
        if result['exit_code'] != EXIT_CODES[report['status']]:
            raise ValueError('exit_report_mismatch')
        return report
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return failure('terminal_report_unverified')


def run_standalone_audit(ctx, config, target):
    try:
        cfg = validate_policy_config(config)
        selected = resolve_native_path(target)
        selected = Path(safe_lexical_guard(selected, cfg['allowed_roots']))
        scratch = private_scratch(cfg['scratch_dir'])
        separate_paths(selected, scratch)
        cmd = build_cli_command(str(selected), str(scratch), cfg)
        result = ctx.dispatch_tool('terminal', {'command': shlex.join(cmd), 'timeout': cfg['timeout_seconds'] + 10})
        return validate_terminal_result(result)
    except PermissionError:
        return failure('target_outside_allowed_roots', 'DENIED')
    except Exception:
        return failure('invalid_configuration_or_path')
