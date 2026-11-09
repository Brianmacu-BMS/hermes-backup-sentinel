"""Exercise the actual deterministic source-only packaging command."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-release-test-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def build(self, path):
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_release.py"), "--output", str(path)],
            cwd=ROOT, capture_output=True, text=True, timeout=30)

    def test_reproducible_source_package_and_manifest(self):
        first, second = self.folder / "one.zip", self.folder / "two.zip"
        a, b = self.build(first), self.build(second)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(b.returncode, 0, b.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        receipt = json.loads(a.stdout)
        self.assertEqual(receipt["sha256"], hashlib.sha256(first.read_bytes()).hexdigest())
        with zipfile.ZipFile(first) as archive:
            manifest = json.loads(archive.read("backup-sentinel/SOURCE-MANIFEST.json"))
            expected = {"backup-sentinel/" + name for name in manifest["files"]} | {"backup-sentinel/SOURCE-MANIFEST.json"}
            self.assertEqual(set(archive.namelist()), expected)
            self.assertEqual(len(archive.namelist()), len(expected))
            for name, facts in manifest["files"].items():
                body = archive.read("backup-sentinel/" + name)
                self.assertEqual(hashlib.sha256(body).hexdigest(), facts["sha256"])
                self.assertEqual(len(body), facts["bytes"])
                self.assertNotIn("__pycache__", name)
                self.assertFalse(name.endswith((".db", ".sqlite", ".pyc", ".zip", ".tar.gz")), name)
                self.assertFalse(Path(name).name.startswith(".env"), name)
            self.assertIn("backup-sentinel/plugin.yaml", expected)
            self.assertIn("backup-sentinel/backup_sentinel/worker.py", expected)
            self.assertIsNone(archive.testzip())

    def test_existing_output_not_overwritten(self):
        target = self.folder / "existing.zip"
        target.write_bytes(b"PRESERVE-THIS-EXISTING-ARTIFACT")
        result = self.build(target)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b"PRESERVE-THIS-EXISTING-ARTIFACT")

    def test_output_inside_source_refused(self):
        result = self.build(ROOT / "artifacts/refused-test.zip")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the source tree", result.stderr)
        self.assertFalse((ROOT / "artifacts/refused-test.zip").exists())

if __name__ == "__main__":
    unittest.main()
