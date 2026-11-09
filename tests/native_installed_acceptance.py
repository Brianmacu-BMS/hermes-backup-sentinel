#!/usr/bin/env python3
"""Native acceptance, restricted to disposable GitHub-hosted runners.

The runner is the machine boundary, not a profile or environment flag. The
pre-SDK guard refuses every mode locally. Ordinary discovery runs guard tests
only; no SDK discovery, installation or activation is performed by this module
at import time. Fixtures are newly generated synthetic archives/databases.
"""
import argparse
from datetime import date, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tarfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def runner_guard():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'Refusing installed acceptance outside a disposable GitHub-hosted runner')
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    for name in ('HOME', 'HERMES_HOME', 'HERMES_RUNTIME_DIR', 'TMPDIR'):
        path = Path(os.environ[name]).resolve(strict=True)
        require(path.is_relative_to(temporary) and path != temporary,
                'Acceptance state must be below RUNNER_TEMP: ' + name)
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    core = Path(os.environ['HERMES_CORE_ROOT']).resolve(strict=True)
    source = Path(os.environ['BACKUP_SENTINEL_SOURCE']).resolve(strict=True)
    require(core.is_relative_to(workspace) and source.is_relative_to(workspace)
            and core != source, 'Separate runner-owned source checkouts required')
    for name in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENROUTER_API_KEY',
                 'NOUS_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_API_KEY', 'LITELLM_API_KEY',
                 'HERMES_YOLO'):
        require(not os.environ.get(name), 'Provider credentials or YOLO are not allowed')
    return core, source


def decode(value):
    return json.loads(value) if isinstance(value, str) else value


def native_host(core):
    sys.path.insert(0, str(core))
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from model_tools import discover_builtin_tools, handle_function_call
    from tools.registry import registry, session_tool_scope
    discover_builtin_tools()
    discover_plugins()
    manager = get_plugin_manager()
    rows = [r for r in manager.list_plugins() if r['name'] == 'backup-sentinel']
    require(len(rows) == 1 and rows[0]['enabled'] is True and not rows[0]['error'],
            'Installed plugin was not discovered and enabled')
    require(registry.get_entry('backup_sentinel_audit', scope=manager.scope_key) is not None,
            'Native registered tool missing')
    require('audit-backups' in manager.list_plugin_skills('backup-sentinel'),
            'Namespaced skill missing')

    def dispatch(args):
        with session_tool_scope(manager.scope_key):
            return decode(handle_function_call('backup_sentinel_audit', args,
                          enabled_tools=['backup_sentinel_audit', 'terminal']))
    return manager, registry, dispatch, rows[0]


def require_good(report):
    require(report.get('status') == 'OK' and report.get('scratch_cleaned') is True
            and report.get('restore_tested') is False
            and report.get('coverage') == 'archive_and_sqlite'
            and set(report.get('checks', {}).values()) == {'ok'},
            'Complete synthetic archive/SQLite audit did not pass: ' + json.dumps(report))


def probe(core, mode, candidate):
    from unittest.mock import patch
    manager, registry, dispatch, discovered = native_host(core)
    terminal = registry.get_entry('terminal', scope=manager.scope_key)
    require(terminal is not None, 'Native terminal registration missing')
    original = terminal.handler
    observed = []

    def observe(args, **kwargs):
        result = original(args, **kwargs)
        observed.append({'args': args, 'result': decode(result)})
        return result

    scratch = Path(os.environ['HERMES_HOME']) / 'scratch'
    before = sorted(p.name for p in scratch.iterdir())
    with patch.object(terminal, 'handler', observe):
        report = dispatch({'target': str(candidate)})
    if mode in ('default', 'outside'):
        require(not observed, 'Refused target/configuration reached terminal execution')
        require(report.get('status') == ('ERROR' if mode == 'default' else 'DENIED'),
                'Default-disabled/outside-root refusal lost: ' + json.dumps(report))
    else:
        require(len(observed) == 1, 'Expected exactly one real terminal dispatch')
        argv = shlex.split(observed[0]['args']['command'])
        cli = Path(os.environ['HERMES_HOME']) / 'plugins/backup-sentinel/backup_sentinel/cli.py'
        require(argv[:4] == [sys.executable, '-I', '-B', str(cli)]
                and argv[4] == str(candidate), 'Fixed installed CLI/target dispatch changed')
        transport = observed[0]['result']
        if mode == 'denied':
            require(transport.get('exit_code') == -1 and report.get('status') == 'DENIED'
                    and 'deny' in json.dumps(transport).lower(), 'Real deny policy not observed')
        else:
            require(transport.get('exit_code') == 0, 'Allowed real terminal process failed')
            require_good(report)
    require(sorted(p.name for p in scratch.iterdir()) == before, 'Probe scratch was not cleaned')
    return {'probe': mode, 'discovered': discovered, 'report': report,
            'terminal_dispatches': observed, 'scratch_unchanged': True}


def synthetic_archive(folder, stamp, database):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / ('backup-' + stamp.strftime('%Y%m%d') + '.tar.gz')
    with tarfile.open(path, 'w:gz') as archive:
        member = tarfile.TarInfo('.hermes/state.db')
        member.size = len(database)
        archive.addfile(member, io.BytesIO(database))
    return path


def session_paths(home, dispatch, database, today):
    from agent.runtime_cwd import set_session_cwd, reset_session_cwd, resolve_agent_cwd
    from hermes_cli.plugins import get_plugin_command_handler
    process = Path.cwd()
    slash = get_plugin_command_handler('backup-sentinel')
    require(callable(slash), 'Real discovered slash handler missing')
    records = []
    for label, stamp in (('one session', today), ('second session', today - timedelta(days=1))):
        session = home / 'fixtures' / label
        archive = synthetic_archive(session / 'backups', stamp, database)
        token = set_session_cwd(str(session))
        try:
            require(resolve_agent_cwd() == session and process != session, 'Session cwd not bound')
            for report in (dispatch({'target': 'backups'}), decode(slash('backups'))):
                require_good(report)
                require(report['selected_date'] == stamp.isoformat(), 'Wrong session archive selected')
            alias = session / 'alias'
            alias.symlink_to(session / 'backups', target_is_directory=True)
            require(dispatch({'target': 'alias/../backups'})['status'] != 'OK',
                    'Tool erased a lexical alias')
            require(decode(slash('alias/../backups'))['status'] != 'OK',
                    'Slash erased a lexical alias')
        finally:
            reset_session_cwd(token)
        records.append({'session': str(session), 'archive': str(archive),
                        'selected_date': stamp.isoformat()})
    require(Path.cwd() == process, 'Native handlers changed process cwd')
    return {'ok': True, 'process_cwd': str(process), 'sessions': records,
            'tool_and_slash_relative_paths_verified': True, 'context_switch_verified': True,
            'lexical_alias_refused': True, 'process_cwd_unchanged': True}


def main(core, source):
    home = Path(os.environ['HERMES_HOME'])
    bindir = home / 'acceptance-bin'
    bindir.mkdir()
    launcher = bindir / 'hermes'
    launcher.write_text('#!/bin/sh\nexec ' + shlex.join([sys.executable, str(core / 'hermes')]) + ' "$@"\n')
    launcher.chmod(0o755)
    os.environ['PATH'] = str(bindir) + os.pathsep + os.environ['PATH']
    installed = home / 'plugins' / 'backup-sentinel'
    files = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z']).decode().split('\0')
    hashes = {}
    for name in filter(None, files):
        data = (source / name).read_bytes()
        require((installed / name).read_bytes() == data, 'Installed file differs: ' + name)
        hashes[name] = hashlib.sha256(data).hexdigest()
    cli = [sys.executable, str(core / 'hermes')]
    runs = []

    def run(label, args, expected=0, cwd=core):
        done = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=300)
        runs.append({'label': label, 'args': args, 'exit_code': done.returncode,
                     'stdout': done.stdout, 'stderr': done.stderr})
        require(done.returncode == expected, label + ' failed: ' + done.stderr[-3000:])
        return done.stdout

    scratch = home / 'scratch'
    scratch.mkdir(mode=0o700)
    fixtures = home / 'fixtures'
    fixtures.mkdir()
    today = date.today()
    database_file = fixtures / 'synthetic.db'
    with sqlite3.connect(database_file) as connection:
        connection.execute('CREATE TABLE synthetic(id INTEGER PRIMARY KEY)')
    connection.close()
    database = database_file.read_bytes()
    good = synthetic_archive(fixtures / 'good archives', today, database)
    corrupt = fixtures / 'bad archives' / good.name
    corrupt.parent.mkdir()
    corrupt.write_bytes(b'not a gzip stream')
    archive_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (good, corrupt)}
    default = run('default-disabled', [sys.executable, __file__, '--probe', 'default', str(good)])
    for key, value in {'allowed_roots': [str(fixtures)], 'scratch_dir': str(scratch)}.items():
        run('configure-' + key, cli + ['config', 'set',
            'plugins.entries.backup-sentinel.settings.' + key, json.dumps(value)])
    outside = home / ('outside-' + good.name)
    outside.write_bytes(b'owned, outside allowed roots')
    refused = run('outside-root', [sys.executable, __file__, '--probe', 'outside', str(outside)])
    manager, registry, dispatch, discovered = native_host(core)
    require_good(dispatch({'target': str(good)}))
    broken = dispatch({'target': str(corrupt)})
    require(broken.get('status') == 'INVALID' and broken.get('reason') == 'gzip_invalid',
            'Corrupt archive finding was not preserved: ' + json.dumps(broken))
    from hermes_cli.plugins import get_plugin_command_handler
    slash = get_plugin_command_handler('backup-sentinel')
    require(callable(slash), 'Native slash discovery failed')
    require_good(decode(slash(shlex.quote(str(good)))))
    require('Usage' in slash(shlex.quote(str(good)) + ' --json'), 'Slash accepted policy overrides')
    paths_receipt = session_paths(home, dispatch, database, today)
    require('0.1.0' in run('cli-version', cli + ['backup-sentinel', '--version']), 'CLI version missing')
    run('cli-missing-arguments', cli + ['backup-sentinel'], 2)
    common = ['--scratch-dir', str(scratch), '--json']
    missing = decode(run('cli-nonexistent', cli + ['backup-sentinel', str(fixtures / 'absent')] + common, 4))
    require(missing['status'] == 'ERROR', 'Missing CLI target did not fail closed')
    require_good(decode(run('cli-good', cli + ['backup-sentinel', str(good)] + common)))
    bad_cli = decode(run('cli-corrupt', cli + ['backup-sentinel', str(corrupt)] + common, 2))
    require(bad_cli['status'] == 'INVALID', 'Native CLI lost corruption exit status')
    require_good(decode(run('cli-relative', cli + ['backup-sentinel', 'backups'] + common,
                           cwd=Path(paths_receipt['sessions'][0]['session']))))
    alias = fixtures / 'alias'
    alias.symlink_to(good)
    require(dispatch({'target': str(alias)})['status'] != 'OK', 'Native tool accepted alias')
    run('cli-alias-refusal', cli + ['backup-sentinel', str(alias)] + common, 4)
    run('policy-deny', cli + ['config', 'set', 'approvals.deny', '["*backup_sentinel/cli.py*"]'])
    denied = run('real-policy-denial', [sys.executable, __file__, '--probe', 'denied', str(good)])
    run('remove-owned-test-deny', cli + ['config', 'set', 'approvals.deny', '[]'])
    allowed = run('real-allowed-audit', [sys.executable, __file__, '--probe', 'allowed', str(good)])
    probes = [decode(next(line.split('PROBE_RESULT=', 1)[1] for line in text.splitlines()
                          if line.startswith('PROBE_RESULT='))) for text in (default, refused, denied, allowed)]
    run('doctor-qualified-source', cli + ['plugins', 'doctor', str(source), '--ci'])
    qualification = decode(run('validate-qualified-source', cli +
                         ['plugins', 'validate', str(source), '--install-deps', '--json']))
    require(qualification.get('ok') is True and qualification.get('checks')
            and all(c.get('ok') is True for c in qualification['checks']), 'Full qualification failed')
    for name, digest in hashes.items():
        require(hashlib.sha256((installed / name).read_bytes()).hexdigest() == digest
                and hashlib.sha256((source / name).read_bytes()).hexdigest() == digest,
                'Source bytes changed during acceptance: ' + name)
    for path, digest in archive_hashes.items():
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest, 'Archive was modified')
    require(not list(scratch.iterdir()), 'Private scratch not empty after acceptance')
    from pm import paths
    from pm.environments import selected_venv
    require(Path(paths.store_root()).resolve() == Path(os.environ['HERMES_RUNTIME_DIR']).resolve(),
            'PM escaped the runner-owned tool store')
    selected = Path(selected_venv(core)).resolve()
    require(selected.is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()), 'PM environment escaped runner')
    receipt = {'ok': True, 'source_commit': subprocess.check_output(
        ['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip(),
        'hermes_commit': subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip(),
        'runner': os.environ['RUNNER_ENVIRONMENT'], 'home': str(home), 'python': sys.executable,
        'selected_venv': str(selected), 'installed': str(installed), 'installed_files': hashes,
        'discovered': discovered, 'runs': runs, 'probes': probes, 'session_paths': paths_receipt,
        'source_qualification': qualification, 'source_qualification_install_deps': True,
        'synthetic_fixtures_only': True, 'archive_hashes_unchanged': archive_hashes,
        'scratch_empty': True, 'activation': 'disposable GitHub runner only',
        'approval_scope': 'real policy denial; not interactive approval UI acceptance',
        'models_called': False, 'certified': False}
    print('ACCEPTANCE_RECEIPT=' + json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    try:
        core, source = runner_guard()
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--guard-only', action='store_true')
        parser.add_argument('--probe', choices=['default', 'outside', 'denied', 'allowed'])
        parser.add_argument('candidate', nargs='?')
        args = parser.parse_args()
        if args.guard_only:
            print(json.dumps({'runner_guard': 'passed', 'activation_performed': False}))
        elif args.probe:
            require(args.candidate is not None, 'Probe candidate required')
            print('PROBE_RESULT=' + json.dumps(probe(core, args.probe, Path(args.candidate))))
        else:
            main(core, source)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}), file=sys.stderr)
        raise SystemExit(2)
