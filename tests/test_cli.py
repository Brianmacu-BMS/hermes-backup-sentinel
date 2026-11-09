"""Actual standalone process tests; all backups are synthetic."""
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sentinel-cli-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.backups = self.root / "backups"
        self.backups.mkdir(mode=0o700)

    def invoke(self, *args):
        return subprocess.run([sys.executable, "-B", "-m", "backup_sentinel", *map(str, args)],
            cwd=ROOT, capture_output=True, text=True, timeout=20)

    def archive(self, corrupt_db=False):
        db = self.root / "synthetic.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE example(id INTEGER PRIMARY KEY)")
        con.commit()
        con.close()
        payload = b"not-a-database-CANARY-DO-NOT-PRINT" if corrupt_db else db.read_bytes()
        target = self.backups / "backup-20261108.tar.gz"
        with tarfile.open(target, "w:gz") as tf:
            info = tarfile.TarInfo(".hermes/state.db")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        return target

    def test_help(self):
        proc = self.invoke("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--scratch-dir", proc.stdout)

    def test_version(self):
        proc = self.invoke("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("0.1.0", proc.stdout)

    def test_real_process_good_sqlite(self):
        proc = self.invoke(self.archive(), "--scratch-dir", self.scratch,
            "--required", ".hermes/state.db", "--sqlite", ".hermes/state.db", "--now", "2026-11-08", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "OK")
        self.assertIs(report["restore_tested"], False)
        self.assertIs(report["scratch_cleaned"], True)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_missing_not_green(self):
        empty = self.root / "empty"
        empty.mkdir()
        proc = self.invoke(empty, "--scratch-dir", self.scratch, "--now", "2026-11-08", "--json")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["status"], "MISSING")

    def test_corrupt_database_nonzero_and_no_payload(self):
        proc = self.invoke(self.archive(True), "--scratch-dir", self.scratch,
            "--required", ".hermes/state.db", "--sqlite", ".hermes/state.db", "--now", "2026-11-08", "--json")
        self.assertNotEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "INVALID")
        self.assertNotIn("CANARY", proc.stdout + proc.stderr)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_invalid_options_refused(self):
        proc = self.invoke(self.root, "--scratch-dir", self.scratch, "--timeout-seconds", "nan", "--json")
        self.assertNotEqual(proc.returncode, 0)

    def test_direct_script_isolated_python(self):
        proc = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "backup_sentinel" / "cli.py"),
            "--version"], cwd=self.root, text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("0.1.0", proc.stdout)

if __name__ == "__main__":
    unittest.main()
