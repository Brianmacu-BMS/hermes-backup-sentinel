"""Additional stdlib smoke coverage; no pytest-only uncollected tests."""
import gzip
import io
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest

from backup_sentinel.model import AuditPolicy
from backup_sentinel.supervisor import run_audit


class EngineSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-smoke-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backups = self.root / 'backups'; self.backups.mkdir(mode=0o700)
        self.scratch = self.root / 'scratch'; self.scratch.mkdir(mode=0o700)
        path = self.root / 'synthetic.db'
        conn = sqlite3.connect(path); conn.execute('CREATE TABLE t(id INTEGER PRIMARY KEY)'); conn.commit(); conn.close()
        self.db = path.read_bytes()

    def make(self, prefix='backup-', entries=None):
        path = self.backups / (prefix + '20261108.tar.gz')
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in (entries or {'.hermes/state.db': self.db}).items():
                info = tarfile.TarInfo(name); info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def test_custom_literal_prefix(self):
        self.make('app-daily-')
        result = run_audit(str(self.backups), AuditPolicy(prefix='app-daily-'), str(self.scratch), '2026-11-08')
        self.assertEqual(result['status'], 'OK', result)

    def test_two_explicit_database_members(self):
        self.make(entries={'first.db': self.db, 'second.db': self.db})
        policy = AuditPolicy(required_members=('first.db', 'second.db'), sqlite_members=('first.db', 'second.db'))
        result = run_audit(str(self.backups), policy, str(self.scratch), '2026-11-08')
        self.assertEqual(result['status'], 'OK', result)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_required_presence_without_database_parsing(self):
        self.make(entries={'metadata.txt': b'synthetic-only'})
        policy = AuditPolicy(required_members=('metadata.txt',), sqlite_members=())
        result = run_audit(str(self.backups), policy, str(self.scratch), '2026-11-08')
        self.assertEqual(result['status'], 'OK', result)
        self.assertEqual(result['checks']['sqlite'], 'not_requested')

if __name__ == '__main__':unittest.main()
