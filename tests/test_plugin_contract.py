"""Exercise plugin registration, schemas, and integration wrappers — fake ctx only, no Hermes loader."""
import importlib.util
import json
import math
import os
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Insert ROOT so backup_sentinel.schemas etc. are importable
sys.path.insert(0, str(ROOT))


class Host:
    """Minimal fake ctx capturing registration calls."""
    def __init__(self):
        self.tools = {}
        self.commands = {}
        self.cli = {}
        self.config = {}
        self.dispatches = []
        self.reply = {'error': 'Approval denied', 'exit_code': -1, 'output': ''}

    def register_tool(self, **kw):
        self.tools[kw['name']] = kw

    def register_command(self, **kw):
        self.commands[kw['name']] = kw

    def register_cli_command(self, **kw):
        self.cli[kw['name']] = kw

    def register_skill(self, name, path):
        pass

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def dispatch_tool(self, name, arguments):
        self.dispatches.append((name, arguments))
        return self.reply


ROOT_INIT = ROOT / '__init__.py'
PLUGIN_YAML = ROOT / 'plugin.yaml'


def complete_report():
    return {'status': 'OK', 'schema_version': 1, 'reason': 'ok',
        'checks': {key: 'ok' for key in ('freshness', 'gzip', 'tar', 'required', 'sqlite')},
        'coverage': 'archive_and_sqlite', 'restore_tested': False,
        'scratch_cleaned': True, 'selected_date': '2026-11-08'}


# =========================================================================
# RED phase: these imports will fail (ImportError) before implementation.
# Move to GREEN by creating backup_sentinel/schemas.py and integration.py.
# =========================================================================
class TestSchemasContract(unittest.TestCase):
    """Config schema validation — no Hermes runtime needed."""

    @classmethod
    def setUpClass(cls):
        from backup_sentinel import schemas as S
        cls.S = S

    def test_rejects_bool_as_int(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_numeric('max_age_days', True, 1, 365)

    def test_rejects_nan(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_numeric('max_compressed_bytes', float('nan'), 1, 1_000_000_000)

    def test_rejects_infinity(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_numeric('timeout_seconds', float('inf'), 1, 300)

    def test_rejects_out_of_range(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_numeric('max_age_days', 999, 1, 365)

    def test_accepts_valid_number(self):
        val = self.S.validate_numeric('max_age_days', 2, 1, 365)
        self.assertEqual(val, 2)

    def test_rejects_missing_allowed_roots(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_policy_config({})

    def test_rejects_empty_allowed_roots(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_policy_config({'allowed_roots': [], 'scratch_dir': '/tmp/s'})

    def test_rejects_unknown_keys(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_policy_config({
                'allowed_roots': ['/home'], 'scratch_dir': '/tmp/s', 'bogus_key': 1,
            })

    def test_rejects_non_dict_config(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_policy_config('not-a-dict')

    def test_accepts_minimal_valid_config(self):
        cfg = self.S.validate_policy_config({
            'allowed_roots': ['/home/backups'],
            'scratch_dir': '/tmp/sentinel',
        })
        self.assertEqual(cfg['prefix'], 'backup-')
        self.assertIsInstance(cfg['max_age_days'], int)
        self.assertEqual(cfg['required_members'], ['.hermes/state.db'])
        self.assertEqual(cfg['sqlite_members'], ['.hermes/state.db'])
        self.assertIn('max_compressed_bytes', cfg)

    def test_full_config_with_optional_lists(self):
        cfg = self.S.validate_policy_config({
            'allowed_roots': ['/mnt/backup', '/home/user'],
            'scratch_dir': '/tmp/scratch',
            'prefix': 'weekly-',
            'required_members': ['.hermes/state.db'],
            'sqlite_members': ['.hermes/state.db'],
        })
        self.assertEqual(cfg['prefix'], 'weekly-')
        self.assertEqual(cfg['required_members'], ['.hermes/state.db'])

    def test_string_member_list_items(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_policy_config({
                'allowed_roots': ['/home'],
                'scratch_dir': '/tmp/s',
                'required_members': [42],
            })

    def test_prefix_must_be_string(self):
        with self.assertRaises(self.S.ConfigValidationError):
            self.S.validate_policy_config({
                'allowed_roots': ['/home'],
                'scratch_dir': '/tmp/s',
                'prefix': 123,
            })

    def test_limits_enumeration(self):
        known = set(self.S.LIMITS)
        expected = {'max_age_days', 'max_compressed_bytes', 'max_uncompressed_bytes',
                    'max_db_bytes', 'max_members', 'timeout_seconds'}
        self.assertEqual(known, expected)


class TestIntegrationContract(unittest.TestCase):
    """Integration wrapper tests — no actual subprocess, fake ctx only."""

    @classmethod
    def setUpClass(cls):
        from backup_sentinel import integration as I
        cls.I = I

    def setUp(self):
        self.host = Host()
        self.tmp = tempfile.TemporaryDirectory(prefix='sentinel-test-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.scratch = Path(self.tmp.name) / 'scratch'
        self.scratch.mkdir(mode=0o700)
        self.tmpname = Path(self.tmp.name)
        self.backups = self.tmpname / 'backups'
        self.backups.mkdir(mode=0o700)

    def test_resolve_native_path_absolute_passthrough(self):
        result = self.I.resolve_native_path('/tmp/foo')
        self.assertEqual(result, Path('/tmp/foo'))

    def test_resolve_native_path_rejects_empty(self):
        with self.assertRaises((ValueError, TypeError)):
            self.I.resolve_native_path('')

    def test_safe_lexical_guard_allows_under_root(self):
        root_dir = str(self.tmpname)
        result = self.I.safe_lexical_guard(str(self.tmpname), [root_dir])
        self.assertEqual(result, str(self.tmpname.resolve()))

    def test_safe_lexical_guard_blocks_outside_root(self):
        with self.assertRaises(PermissionError):
            self.I.safe_lexical_guard('/etc/passwd', [str(self.tmpname)])

    def test_safe_lexical_guard_empty_roots(self):
        with self.assertRaises(PermissionError):
            self.I.safe_lexical_guard(str(self.tmpname), [])

    def test_build_cli_command_has_required_flags(self):
        cfg = {
            'prefix': 'backup-', 'max_age_days': 2,
            'max_compressed_bytes': 268435456, 'max_uncompressed_bytes': 536870912,
            'max_db_bytes': 33554432, 'max_members': 4096, 'timeout_seconds': 30,
            'required_members': [], 'sqlite_members': [],
        }
        cmd = self.I.build_cli_command('/target/archive.tar.gz', '/scratch', cfg)
        cmd_str = ' '.join(cmd)
        self.assertIn('--scratch-dir', cmd_str)
        self.assertIn('/scratch', cmd_str)
        self.assertIn('--json', cmd_str)
        self.assertIn('--max-age-days', cmd_str)
        self.assertIn('268435456', cmd_str)
        self.assertNotIn('--required', cmd_str)

    def test_build_cli_with_required_members(self):
        cfg = {
            'prefix': 'backup-', 'max_age_days': 2,
            'max_compressed_bytes': 268435456, 'max_uncompressed_bytes': 536870912,
            'max_db_bytes': 33554432, 'max_members': 4096, 'timeout_seconds': 30,
            'required_members': ['.hermes/state.db'],
            'sqlite_members': ['.hermes/state.db'],
        }
        cmd = self.I.build_cli_command('/target', '/scratch', cfg)
        cmd_str = ' '.join(cmd)
        self.assertIn('--policy-json', cmd_str)
        self.assertIn('.hermes/state.db', cmd_str)
        self.assertIn('sqlite_members', cmd_str)

    def test_validate_terminal_result_ok(self):
        result = {'exit_code': 0, 'output': json.dumps(complete_report())}
        report = self.I.validate_terminal_result(result)
        self.assertEqual(report['status'], 'OK')

    def test_validate_terminal_result_nonzero_exit(self):
        result = {'exit_code': 1, 'output': json.dumps({'status': 'ERROR'})}
        report = self.I.validate_terminal_result(result)
        self.assertIn('error', report)

    def test_validate_terminal_result_denied(self):
        result = {'exit_code': -1, 'error': 'Approval denied', 'output': ''}
        report = self.I.validate_terminal_result(result)
        self.assertIn('error', report)

    def test_validate_refuses_bool_exit_code(self):
        result = {'exit_code': False, 'output': json.dumps({'status': 'OK'})}
        report = self.I.validate_terminal_result(result)
        self.assertIn('error', report)

    def test_validate_refuses_string_exit_code(self):
        result = {'exit_code': '0', 'output': json.dumps({'status': 'OK'})}
        report = self.I.validate_terminal_result(result)
        self.assertIn('error', report)

    def test_validate_refuses_non_dict_result(self):
        report = self.I.validate_terminal_result('not-a-dict')
        self.assertIn('error', report)

    def test_validate_refuses_bad_json_output(self):
        result = {'exit_code': 0, 'output': 'not-json-at-all'}
        report = self.I.validate_terminal_result(result)
        self.assertIn('error', report)

    def test_run_standalone_audit_denies_outside_root(self):
        self.host.config = {
            'allowed_roots': ['/home/backups'],
            'scratch_dir': '/tmp/s',
        }
        report = self.I.run_standalone_audit(self.host, self.host.config, '/etc/passwd')
        self.assertEqual(report['status'], 'DENIED', report)

    def test_run_standalone_audit_no_dispatch_if_denied(self):
        self.host.config = {
            'allowed_roots': ['/home/backups'],
            'scratch_dir': '/tmp/s',
        }
        self.I.run_standalone_audit(self.host, self.host.config, '/etc/passwd')
        self.assertEqual(self.host.dispatches, [])

    def test_run_standalone_audit_dispatch_on_valid_target(self):
        self.host.config = {
            'allowed_roots': [str(self.backups)],
            'scratch_dir': str(self.scratch),
        }
        self.host.reply = {'exit_code': 0, 'output': json.dumps(complete_report())}
        report = self.I.run_standalone_audit(self.host, self.host.config, str(self.backups))
        self.assertEqual(len(self.host.dispatches), 1)
        self.assertEqual(self.host.dispatches[0][0], 'terminal')

    def test_run_preserves_approval_denial(self):
        self.host.config = {
            'allowed_roots': [str(self.backups)],
            'scratch_dir': str(self.scratch),
        }
        report = self.I.run_standalone_audit(self.host, self.host.config, str(self.backups))
        self.assertEqual(report['status'], 'DENIED')

    def test_run_with_bad_config_returns_error_not_denied(self):
        report = self.I.run_standalone_audit(self.host, {}, str(self.tmpname))
        self.assertEqual(report['status'], 'ERROR')
        self.assertIn('error', report)

    def test_run_with_empty_target_returns_error(self):
        report = self.I.run_standalone_audit(self.host, {}, '')
        self.assertEqual(report['status'], 'ERROR')

    def test_duplicate_json_handling_strict_bool_int(self):
        result = {'exit_code': True, 'output': json.dumps({'status': 'OK'})}
        report = self.I.validate_terminal_result(result)
        self.assertIn('error', report)

        result2 = {'exit_code': 1, 'output': json.dumps({'status': 'ERROR'})}
        report2 = self.I.validate_terminal_result(result2)
        self.assertIn('error', report2)


class TestPluginRegistration(unittest.TestCase):
    """Plugin __init__.py registration without Hermes loader — fake Host only."""

    @classmethod
    def setUpClass(cls):
        if not ROOT_INIT.is_file():
            raise unittest.SkipTest('Root __init__.py not yet implemented')
        spec = importlib.util.spec_from_file_location(
            'backup_sentinel_plugin', ROOT_INIT,
            submodule_search_locations=[str(ROOT)],
        )
        cls.plugin = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.plugin
        spec.loader.exec_module(cls.plugin)

    def test_version_constant(self):
        self.assertEqual(self.plugin.VERSION, '0.1.0')

    def test_tool_schema_defined(self):
        self.assertIn('name', self.plugin.SCHEMA)
        self.assertEqual(self.plugin.SCHEMA['name'], 'backup_sentinel_audit')
        self.assertEqual(self.plugin.SCHEMA['parameters'].get('additionalProperties'), False)
        self.assertIn('target', self.plugin.SCHEMA['parameters'].get('properties', {}))

    def test_register_tool_surfaces(self):
        host = Host()
        self.plugin.register(host)
        self.assertIn('backup_sentinel_audit', host.tools)
        tool = host.tools['backup_sentinel_audit']
        self.assertEqual(tool['toolset'], 'backup_sentinel')

    def test_register_command_surfaces(self):
        host = Host()
        self.plugin.register(host)
        self.assertIn('backup-sentinel', host.commands)

    def test_register_cli_command_surfaces(self):
        host = Host()
        self.plugin.register(host)
        self.assertIn('backup-sentinel', host.cli)

    def test_tool_schema_only_has_target(self):
        props = self.plugin.SCHEMA['parameters']['properties']
        self.assertEqual(set(props.keys()), {'target'})

    def test_tool_handler_returns_json_string(self):
        host = Host()
        host.config = {
            'allowed_roots': ['/tmp'],
            'scratch_dir': '/tmp/s',
        }
        self.plugin.register(host)
        handler = host.tools['backup_sentinel_audit']['handler']
        result = handler({'target': '/tmp'})
        self.assertIsInstance(result, str)
        parsed = json.loads(result)
        self.assertIn('status', parsed)

    def test_handle_bad_target_does_not_raise(self):
        host = Host()
        host.config = {}
        self.plugin.register(host)
        handler = host.tools['backup_sentinel_audit']['handler']
        result = handler({})
        self.assertIsInstance(result, str)

    def test_slash_empty_returns_usage(self):
        result = self.plugin.slash('')
        self.assertIn('Usage', result)

    def test_slash_exception_returns_usage(self):
        result = self.plugin.slash('not-a-path')
        self.assertIn('Usage', result)


class TestPluginYaml(unittest.TestCase):
    """plugin.yaml manifest structure."""

    def test_yaml_exists(self):
        # Use yaml via import to check
        import json as yml
        with open(PLUGIN_YAML) as f:
            manifest = yml.load(f)

        self.assertEqual(manifest.get('name'), 'backup-sentinel')
        self.assertEqual(manifest.get('version'), '0.1.0')
        self.assertIsInstance(manifest.get('description'), str)
        self.assertIn('backup', manifest.get('description', '').lower())

        self.assertIn('provides_tools', manifest)
        self.assertIn('backup_sentinel_audit', manifest['provides_tools'])

        self.assertEqual(manifest.get('provides_hooks'), [])

    def test_platform_linux_only(self):
        import json as yml
        with open(PLUGIN_YAML) as f:
            manifest = yml.load(f)
        platforms = manifest.get('platforms', [])
        self.assertIn('linux', platforms)
        for p in platforms:
            self.assertIn(p, ('linux',))

    def test_requires_hermes_floor(self):
        import json as yml
        with open(PLUGIN_YAML) as f:
            manifest = yml.load(f)
        req = manifest.get('requires_hermes', '')
        self.assertTrue(req.startswith('>='), f'requires_hermes should be a floor: {req}')

    def test_no_python_dependencies(self):
        import json as yml
        with open(PLUGIN_YAML) as f:
            manifest = yml.load(f)
        deps = manifest.get('python_dependencies', [])
        self.assertEqual(deps, [])


if __name__ == '__main__':
    unittest.main()