"""Fault-injected transport tests launch trusted synthetic workers, never Hermes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from backup_sentinel import supervisor as S


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-supervisor-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def worker(self, code, timeout=2):
        file = self.root / 'trusted-fault-worker.py'
        file.write_text(code)
        with patch.object(S, '_WORKER_ARGV', (sys.executable, '-I', '-B', str(file))):
            return S._run_worker(b'{}', timeout)

    def test_actual_wall_timeout_kills_and_reaps_child(self):
        pidfile = self.root / 'pid'
        code = 'import os,time\nfrom pathlib import Path\nPath(' + repr(str(pidfile)) + ').write_text(str(os.getpid()))\ntime.sleep(60)\n'
        start = time.monotonic()
        result = self.worker(code, timeout=1)
        self.assertEqual(result['status'], 'TIMEOUT')
        self.assertLess(time.monotonic() - start, 5)
        pid = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):os.kill(pid, 0)

    def test_stdout_flood_is_bounded(self):
        result = self.worker('import os,time\nos.write(1,b"x"*100000)\ntime.sleep(60)\n')
        self.assertEqual(result['status'], 'ERROR')
        self.assertEqual(result['reason'], 'worker_output_limit')

    def test_stderr_flood_is_bounded(self):
        result = self.worker('import os,time\nos.write(2,b"x"*100000)\ntime.sleep(60)\n')
        self.assertEqual(result['status'], 'ERROR')
        self.assertEqual(result['reason'], 'worker_output_limit')

    def test_malformed_worker_response_not_green(self):
        result = self.worker('print("not-a-report")\n')
        self.assertEqual(result['status'], 'ERROR')

    def test_nonzero_worker_exit_not_green(self):
        value = {'schema_version': 1, 'status': 'OK', 'reason': 'ok',
            'checks': {k: 'ok' for k in ('freshness', 'gzip', 'tar', 'required', 'sqlite')},
            'coverage': 'archive_and_sqlite', 'restore_tested': False,
            'scratch_cleaned': True, 'selected_date': '2026-11-08'}
        result = self.worker('import sys\nprint(' + repr(json.dumps(value)) + ')\nsys.exit(7)\n')
        self.assertEqual(result['status'], 'ERROR')
        self.assertEqual(result['reason'], 'worker_failed')

    def test_parent_environment_not_inherited(self):
        value = {'schema_version': 1, 'status': 'OK', 'reason': 'ok',
            'checks': {k: 'ok' for k in ('freshness', 'gzip', 'tar', 'required', 'sqlite')},
            'coverage': 'archive_and_sqlite', 'restore_tested': False,
            'scratch_cleaned': True, 'selected_date': '2026-11-08'}
        code = 'import os,json\nv=' + repr(value) + '\nif "SENTINEL_TEST_SECRET" in os.environ: v["status"]="ERROR"\nprint(json.dumps(v))\n'
        with patch.dict(os.environ, {'SENTINEL_TEST_SECRET': 'SYNTHETIC-CANARY'}):
            result = self.worker(code)
        self.assertEqual(result['status'], 'OK')

    def test_cleanup_failure_overrides_result(self):
        from backup_sentinel.model import AuditPolicy
        backups = self.root / 'backups'; backups.mkdir(mode=0o700)
        scratch = self.root / 'scratch'; scratch.mkdir(mode=0o700)
        with patch.object(S, '_cleanup_private', return_value=False):
            result = S.run_audit(str(backups), AuditPolicy(), str(scratch), '2026-11-08')
        self.assertEqual(result['status'], 'ERROR')
        self.assertEqual(result['reason'], 'cleanup_failed')
        self.assertIs(result['scratch_cleaned'], False)
        self.assertTrue(list(scratch.iterdir()))
        # Test-owned outer TemporaryDirectory performs the intentionally withheld cleanup.

if __name__ == '__main__':unittest.main()
