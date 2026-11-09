"""CI acceptance must refuse local/self-hosted execution before SDK imports."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parent / 'native_installed_acceptance.py'


class InstalledRunnerGuardTests(unittest.TestCase):
    def refused(self, changes):
        env = dict(os.environ)
        env.pop('GITHUB_ACTIONS', None)
        env.pop('RUNNER_ENVIRONMENT', None)
        env.update(changes)
        # Even a bogus import path cannot reach SDK imports before this refusal.
        env['PYTHONPATH'] = str(SCRIPT.parent / 'absent-sdk')
        result = subprocess.run([sys.executable, str(SCRIPT), '--guard-only'],
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        payload = json.loads(result.stderr)
        self.assertFalse(payload['ok'])
        self.assertIn('Refusing installed acceptance', payload['error'])
        self.assertNotIn('ModuleNotFoundError', result.stderr)

    def test_local_execution_refused_before_import(self):
        self.refused({})

    def test_self_hosted_actions_execution_refused_before_import(self):
        self.refused({'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'})


if __name__ == '__main__':
    unittest.main()