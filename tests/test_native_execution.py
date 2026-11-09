"""Real fixed-CLI execution behind a fake host, not simulated successful audits."""
import argparse
from datetime import date
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import types

from backup_sentinel import integration as I
from backup_sentinel.schemas import validate_policy_config

ROOT = Path(__file__).resolve().parents[1]


def report(status='OK'):
    return {'schema_version': 1, 'status': status, 'reason': 'ok' if status == 'OK' else 'gzip_invalid',
        'checks': {k: 'ok' for k in ('freshness', 'gzip', 'tar', 'required', 'sqlite')},
        'coverage': 'archive_and_sqlite', 'restore_tested': False, 'scratch_cleaned': True,
        'selected_date': date.today().isoformat()}


class ExecutingHost:
    def __init__(self, config, cwd):
        self.config, self.cwd = config, cwd
        self.tools, self.commands, self.cli, self.skills, self.calls = {}, {}, {}, {}, []
    def get_config(self, key, default=None):return self.config.get(key, default)
    def register_tool(self, **kw):self.tools[kw['name']] = kw
    def register_command(self, **kw):self.commands[kw['name']] = kw
    def register_cli_command(self, **kw):self.cli[kw['name']] = kw
    def register_skill(self, name, path):self.skills[name] = path
    def dispatch_tool(self, name, args):
        if name != 'terminal':raise AssertionError('unexpected tool')
        self.calls.append(args)
        proc = subprocess.run(args['command'], shell=True, cwd=self.cwd,
            env={'PATH': os.defpath, 'TMPDIR': os.environ['TMPDIR']},
            capture_output=True, text=True, timeout=args.get('timeout', 20))
        return {'output': proc.stdout, 'exit_code': proc.returncode}


class NativeExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('sentinel_test_native', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
        cls.plugin = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.plugin
        spec.loader.exec_module(cls.plugin)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sentinel-native-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backups = self.root / 'backups'
        self.scratch = self.root / 'scratch'
        self.backups.mkdir(mode=0o700); self.scratch.mkdir(mode=0o700)
        self.cfg = {'allowed_roots': [str(self.backups)], 'scratch_dir': str(self.scratch)}
        self.host = ExecutingHost(self.cfg, self.root)
        self.plugin.register(self.host)
        db = self.root / 'synthetic.db'
        con = sqlite3.connect(db); con.execute('CREATE TABLE t(id INTEGER PRIMARY KEY)'); con.commit(); con.close()
        self.db = db.read_bytes()

    def archive(self, prefix='backup-', corrupt=False):
        path = self.backups / (prefix + date.today().strftime('%Y%m%d') + '.tar.gz')
        if corrupt:
            path.write_bytes(b'broken gzip')
        else:
            with tarfile.open(path, 'w:gz') as tf:
                info = tarfile.TarInfo('.hermes/state.db'); info.size = len(self.db)
                tf.addfile(info, io.BytesIO(self.db))
        return path

    def test_native_tool_executes_from_nonproject_cwd(self):
        path = self.archive()
        actual = json.loads(self.host.tools['backup_sentinel_audit']['handler']({'target': str(path)}))
        self.assertEqual(actual['status'], 'OK', actual)
        self.assertIs(actual['scratch_cleaned'], True)
        self.assertEqual(len(self.host.calls), 1)
        self.assertIn('timeout', self.host.calls[0])
        self.assertNotIn(' -m backup_sentinel', self.host.calls[0]['command'])

    def test_native_slash_performs_real_audit(self):
        path = self.archive()
        actual = json.loads(self.host.commands['backup-sentinel']['handler'](shlex.quote(str(path))))
        self.assertEqual(actual['status'], 'OK', actual)
        self.assertEqual(len(self.host.calls), 1)

    def test_native_slash_cannot_override_operator_policy(self):
        path = self.archive()
        actual = self.host.commands['backup-sentinel']['handler'](shlex.quote(str(path)) + ' --now 1900-01-01')
        self.assertNotIn('completed', actual.lower())
        self.assertEqual(self.host.calls, [])

    def test_native_cli_parser_and_namespace_dispatch(self):
        parser = argparse.ArgumentParser()
        spec = self.host.cli['backup-sentinel']
        spec['setup_fn'](parser)
        args = parser.parse_args([str(self.archive()), '--scratch-dir', str(self.scratch), '--json'])
        with self.assertRaises(SystemExit) as result:
            spec['handler_fn'](args)
        self.assertEqual(result.exception.code, 0)

    def test_skill_registered(self):
        self.assertEqual(set(self.host.skills), {'audit-backups'})
        self.assertTrue(Path(self.host.skills['audit-backups']).is_file())

    def test_shell_metacharacters_remain_literal_arguments(self):
        for prefix in ('backup-;false;', '-backup-'):
            with self.subTest(prefix=prefix):
                self.cfg['prefix'] = prefix
                path = self.archive(prefix=prefix)
                actual = json.loads(self.host.tools['backup_sentinel_audit']['handler']({'target': str(path)}))
                self.assertEqual(actual['status'], 'OK', actual)
                cmd = self.host.calls[-1]['command']
                self.assertEqual(cmd, shlex.join(shlex.split(cmd)))

    def test_real_nonzero_findings_preserved(self):
        path = self.archive(corrupt=True)
        actual = json.loads(self.host.tools['backup_sentinel_audit']['handler']({'target': str(path)}))
        self.assertEqual(actual['status'], 'INVALID', actual)
        self.assertEqual(actual['reason'], 'gzip_invalid')

    def test_symlink_inside_allowed_root_refused_before_dispatch(self):
        path = self.archive()
        alias = self.backups / 'alias.tar.gz'; alias.symlink_to(path)
        actual = I.run_standalone_audit(self.host, self.cfg, str(alias))
        self.assertNotEqual(actual['status'], 'OK')
        self.assertEqual(self.host.calls, [])

    def test_relative_roots_rejected(self):
        with self.assertRaises(ValueError):validate_policy_config({'allowed_roots': ['relative'], 'scratch_dir': str(self.scratch)})

    def test_fractional_limit_rejected(self):
        with self.assertRaises(ValueError):validate_policy_config({**self.cfg, 'max_age_days': 2.5})

    def test_explicit_empty_policy_means_archive_only(self):
        cfg = validate_policy_config({**self.cfg, 'required_members': [], 'sqlite_members': []})
        cmd = I.build_cli_command(str(self.backups), str(self.scratch), cfg)
        self.assertIn('--archive-only', cmd)

    def test_extra_model_arguments_refused_before_dispatch(self):
        self.archive()
        actual = json.loads(self.host.tools['backup_sentinel_audit']['handler']({'target': str(self.backups), 'timeout_seconds': 1}))
        self.assertEqual(actual['status'], 'ERROR')
        self.assertEqual(self.host.calls, [])

    def test_duplicate_report_keys_rejected(self):
        payload = json.dumps(report())[:-1] + ',"status":"INVALID"}'
        self.assertEqual(I.validate_terminal_result({'exit_code': 0, 'output': payload})['status'], 'ERROR')

    def test_boolean_schema_rejected(self):
        payload = report(); payload['schema_version'] = True
        self.assertEqual(I.validate_terminal_result({'exit_code': 0, 'output': json.dumps(payload)})['status'], 'ERROR')

    def test_partial_green_report_rejected(self):
        self.assertEqual(I.validate_terminal_result({'exit_code': 0, 'output': '{"status":"OK","schema_version":1}'})['status'], 'ERROR')

    def test_extra_report_content_rejected(self):
        payload = report(); payload['private_rows'] = 'CANARY'
        actual = I.validate_terminal_result({'exit_code': 0, 'output': json.dumps(payload)})
        self.assertEqual(actual['status'], 'ERROR'); self.assertNotIn('CANARY', json.dumps(actual))

    def test_valid_invalid_report_nonzero_is_not_transport_error(self):
        payload = report('INVALID'); payload['checks']['gzip'] = 'fail'
        actual = I.validate_terminal_result({'exit_code': 2, 'output': json.dumps(payload)})
        self.assertEqual(actual['status'], 'INVALID')

    def test_exit_and_report_disagreement_rejected(self):
        self.assertEqual(I.validate_terminal_result({'exit_code': 0, 'output': json.dumps(report('INVALID'))})['status'], 'ERROR')

    def test_session_relative_native_path_uses_invocation_cwd(self):
        path = self.archive()
        module = types.ModuleType('agent.runtime_cwd')
        module.resolve_agent_cwd = lambda: self.backups
        before = Path.cwd()
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            actual = json.loads(self.host.tools['backup_sentinel_audit']['handler']({'target': path.name}))
        self.assertEqual(actual['status'], 'OK', actual)
        self.assertEqual(Path.cwd(), before)

    def test_relative_alias_rejected_before_resolution(self):
        path = self.archive()
        (self.backups / 'alias').symlink_to(path)
        module = types.ModuleType('agent.runtime_cwd')
        module.resolve_agent_cwd = lambda: self.backups
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            actual = json.loads(self.host.tools['backup_sentinel_audit']['handler']({'target': 'alias'}))
        self.assertEqual(actual['status'], 'ERROR')
        self.assertEqual(self.host.calls, [])

    def test_terminal_json_envelope_supported(self):
        actual = I.validate_terminal_result(json.dumps({'exit_code': 0, 'output': json.dumps(report())}))
        self.assertEqual(actual['status'], 'OK')

    def test_denied_json_envelope_preserved(self):
        actual = I.validate_terminal_result(json.dumps({'exit_code': -1, 'error': 'denied', 'output': ''}))
        self.assertEqual(actual['status'], 'DENIED')

if __name__ == '__main__':unittest.main()
