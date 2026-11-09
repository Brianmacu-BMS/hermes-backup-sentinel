"""Independent behavioral regressions on real synthetic archives/processes."""
import concurrent.futures
from dataclasses import replace
import gzip
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from backup_sentinel.model import AuditPolicy
from backup_sentinel.supervisor import run_audit

NOW = '2026-11-08'
MEMBER = '.hermes/state.db'
CANARY = 'PRIVATE-SYNTHETIC-CANARY-NOT-FOR-REPORTS'

class AdversarialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-adversarial-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backups = self.root / 'backups'
        self.scratch = self.root / 'scratch'
        self.backups.mkdir(mode=0o700)
        self.scratch.mkdir(mode=0o700)
        self.policy = AuditPolicy()
        database = self.root / 'source.db'
        con = sqlite3.connect(database)
        con.executescript('CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id)); INSERT INTO parent VALUES(1); INSERT INTO child VALUES(1,1);')
        con.commit()
        con.close()
        self.database = database.read_bytes()

    def tar_bytes(self, entries=None):
        entries = [(MEMBER, self.database, tarfile.REGTYPE, '')] if entries is None else entries
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tf:
            for name, data, kind, link in entries:
                info = tarfile.TarInfo(name)
                info.type, info.linkname = kind, link
                info.size = len(data) if kind == tarfile.REGTYPE else 0
                tf.addfile(info, io.BytesIO(data) if info.size else None)
        return buf.getvalue()

    def make(self, entries=None, date='20261108', raw=None):
        path = self.backups / ('backup-' + date + '.tar.gz')
        path.write_bytes(gzip.compress(self.tar_bytes(entries)) if raw is None else raw)
        return path

    def audit(self, target=None, policy=None, scratch=None):
        report = run_audit(target=str(target or self.backups), policy=policy or self.policy,
            scratch_root=str(scratch or self.scratch), now=NOW)
        self.assertIs(report['restore_tested'], False)
        self.assertIs(report['scratch_cleaned'], True)
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertEqual(list(self.scratch.iterdir()), [])
        return report

    def test_valid_archive_and_database(self):
        self.make()
        report = self.audit()
        self.assertEqual(report['status'], 'OK', report)
        self.assertEqual(report['checks']['sqlite'], 'ok')

    def test_source_unchanged(self):
        path = self.make()
        before = path.read_bytes(), path.stat().st_mtime_ns
        self.assertEqual(self.audit()['status'], 'OK')
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)

    def test_missing(self):
        self.assertEqual(self.audit()['status'], 'MISSING')

    def test_stale(self):
        self.make(date='20261101')
        self.assertEqual(self.audit()['status'], 'STALE')

    def test_future_blocks_good_older(self):
        self.make(date='20261107')
        self.make(date='20261109')
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_impossible_date_blocks_good_older(self):
        self.make(date='20261107')
        self.make(date='20260230')
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_newest_corrupt_no_fallback(self):
        self.make(date='20261107')
        self.make(raw=b'bad-gzip-' + CANARY.encode())
        report = self.audit()
        self.assertEqual(report['status'], 'INVALID')
        self.assertEqual(report['selected_date'], NOW)

    def test_filename_date_not_mtime(self):
        old = self.make(date='20261107')
        new = self.make()
        os.utime(old, (2000000000, 2000000000))
        os.utime(new, (1000000000, 1000000000))
        self.assertEqual(self.audit()['selected_date'], NOW)

    def test_gzip_bad_crc(self):
        data = bytearray(gzip.compress(self.tar_bytes()))
        data[-8] ^= 1
        self.make(raw=bytes(data))
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_truncated_gzip(self):
        self.make(raw=gzip.compress(self.tar_bytes())[:-5])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_missing_tar_end_marker(self):
        raw = self.tar_bytes()
        end = 512 + ((len(self.database) + 511) // 512) * 512
        self.make(raw=gzip.compress(raw[:end]))
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_nonzero_tar_trailer(self):
        self.make(raw=gzip.compress(self.tar_bytes() + b'junk-' + CANARY.encode()))
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_traversal_member(self):
        self.make(entries=[('../' + CANARY, b'x', tarfile.REGTYPE, '')])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_absolute_member(self):
        self.make(entries=[('/' + CANARY, b'x', tarfile.REGTYPE, '')])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_duplicate_normalized_names(self):
        self.make(entries=[(MEMBER, self.database, tarfile.REGTYPE, ''), ('./' + MEMBER, self.database, tarfile.REGTYPE, '')])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_special_and_fifo_members(self):
        for kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE):
            with self.subTest(kind=kind):
                self.make(entries=[(CANARY, b'', kind, '')])
                self.assertEqual(self.audit()['status'], 'INVALID')

    def test_nonrequired_links_opaque(self):
        self.make(entries=[(MEMBER, self.database, tarfile.REGTYPE, ''), ('link', b'', tarfile.SYMTYPE, '/' + CANARY), ('hard', b'', tarfile.LNKTYPE, '../' + CANARY)])
        self.assertEqual(self.audit()['status'], 'OK')

    def test_required_link_rejected(self):
        self.make(entries=[(MEMBER, b'', tarfile.SYMTYPE, '/' + CANARY)])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_required_directory_rejected(self):
        self.make(entries=[(MEMBER, b'', tarfile.DIRTYPE, '')])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_required_member_missing(self):
        self.make(entries=[('other', b'synthetic', tarfile.REGTYPE, '')])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_bad_database(self):
        self.make(entries=[(MEMBER, CANARY.encode(), tarfile.REGTYPE, '')])
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_foreign_key_violation(self):
        path = self.root / 'fk.db'
        con = sqlite3.connect(path)
        con.executescript('CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE c(pid INTEGER REFERENCES p(id)); INSERT INTO c VALUES(999);')
        con.commit(); con.close()
        self.make(entries=[(MEMBER, path.read_bytes(), tarfile.REGTYPE, '')])
        report = self.audit()
        self.assertEqual(report['status'], 'INVALID')
        self.assertEqual(report['reason'], 'sqlite_foreign_key_failed')

    def test_compressed_budget_is_limit(self):
        self.make()
        self.assertEqual(self.audit(policy=replace(self.policy, max_compressed_bytes=1))['status'], 'LIMIT')

    def test_uncompressed_budget_is_limit(self):
        self.make()
        self.assertEqual(self.audit(policy=replace(self.policy, max_uncompressed_bytes=512))['status'], 'LIMIT')

    def test_database_budget_is_limit(self):
        self.make()
        self.assertEqual(self.audit(policy=replace(self.policy, max_db_bytes=16))['status'], 'LIMIT')

    def test_member_budget_is_limit(self):
        self.make(entries=[(MEMBER, self.database, tarfile.REGTYPE, ''), ('extra', b'x', tarfile.REGTYPE, '')])
        self.assertEqual(self.audit(policy=replace(self.policy, max_members=1))['status'], 'LIMIT')

    def test_directory_entry_budget_is_limit(self):
        self.make()
        for n in range(4):
            (self.backups / ('unrelated-' + str(n))).write_text('x')
        self.assertEqual(self.audit(policy=replace(self.policy, max_members=2))['status'], 'LIMIT')

    def test_large_pax_metadata_is_limit(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tf:
            info = tarfile.TarInfo(MEMBER)
            info.pax_headers = {'comment': CANARY + 'x' * (2 * 1024 * 1024)}
            info.size = len(self.database)
            tf.addfile(info, io.BytesIO(self.database))
        self.make(raw=gzip.compress(buf.getvalue()))
        self.assertEqual(self.audit()['status'], 'LIMIT')

    def test_matching_symlink_candidate_blocks_older(self):
        old = self.make(date='20261107')
        (self.backups / 'backup-20261108.tar.gz').symlink_to(old)
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_symlink_ancestor_refused(self):
        path = self.make()
        alias = self.root / 'alias'
        alias.symlink_to(self.backups, target_is_directory=True)
        self.assertEqual(self.audit(target=alias / path.name)['status'], 'ERROR')

    def test_symlink_dotdot_not_erased(self):
        self.make()
        alias = self.root / 'alias'
        alias.symlink_to(self.backups, target_is_directory=True)
        target = str(alias) + '/../backups/backup-20261108.tar.gz'
        self.assertEqual(self.audit(target=target)['status'], 'ERROR')

    def test_fifo_target_refused_without_blocking(self):
        fifo = self.root / 'backup-20261108.tar.gz'
        os.mkfifo(fifo)
        self.assertEqual(self.audit(target=fifo)['status'], 'ERROR')

    def test_scratch_symlink_refused_before_write(self):
        self.make()
        alias = self.root / 'scratch-alias'
        alias.symlink_to(self.scratch, target_is_directory=True)
        self.assertEqual(self.audit(scratch=alias)['status'], 'ERROR')

    def test_scratch_world_readable_refused(self):
        self.make()
        public = self.root / 'public'
        public.mkdir(mode=0o755)
        self.assertEqual(self.audit(scratch=public)['status'], 'ERROR')
        self.assertEqual(list(public.iterdir()), [])

    def test_scratch_inside_backup_tree_refused(self):
        self.make()
        nested = self.backups / 'scratch'
        nested.mkdir(mode=0o700)
        self.assertEqual(self.audit(scratch=nested)['status'], 'ERROR')
        self.assertEqual(list(nested.iterdir()), [])

    def test_credential_members_never_materialized(self):
        for name in ('.env', '.ENV.production', '.hermes/auth.json', '.ssh/id_ed25519', 'data/credentials.json'):
            with self.subTest(name=name):
                self.make(entries=[(name, self.database, tarfile.REGTYPE, '')])
                policy = replace(self.policy, required_members=(name,), sqlite_members=(name,))
                self.assertEqual(self.audit(policy=policy)['status'], 'ERROR')

    def test_archive_only_explicit_coverage(self):
        self.make(entries=[('data', b'synthetic', tarfile.REGTYPE, '')])
        report = self.audit(policy=replace(self.policy, required_members=(), sqlite_members=()))
        self.assertEqual(report['status'], 'OK')
        self.assertEqual(report['coverage'], 'archive_integrity_only')
        self.assertEqual(report['checks']['sqlite'], 'not_requested')
        self.assertEqual(report['checks']['required'], 'not_requested')

    def test_concurrent_requests(self):
        self.make()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            reports = list(pool.map(lambda _: run_audit(str(self.backups), self.policy, str(self.scratch), NOW), range(4)))
        self.assertTrue(all(r['status'] == 'OK' and r['scratch_cleaned'] is True for r in reports), reports)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_invalid_numeric_policy(self):
        for value in (True, False, 1.5, float('nan'), float('inf'), -1, 10**100):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    replace(self.policy, timeout_seconds=value)

    def test_worker_termination_is_reaped_and_scratch_cleaned(self):
        # A deterministic supervisor deadline, not a CPU-speed-dependent archive.
        # The actual fixed worker is launched; only the parent's clock is advanced.
        self.make()
        from backup_sentinel import supervisor
        original = supervisor.time.monotonic
        count = [0]
        def clock():
            count[0] += 1
            return original() + (1000 if count[0] >= 2 else 0)
        with patch.object(supervisor.time, 'monotonic', clock):
            report = self.audit()
        self.assertEqual(report['status'], 'TIMEOUT', report)

    def test_concatenated_gzip_payload_not_hidden(self):
        self.make(raw=gzip.compress(self.tar_bytes()) + gzip.compress(CANARY.encode()))
        self.assertEqual(self.audit()['status'], 'INVALID')

    def test_concatenated_gzip_second_crc_checked(self):
        second = bytearray(gzip.compress(b'')); second[-8] ^= 1
        self.make(raw=gzip.compress(self.tar_bytes()) + bytes(second))
        report = self.audit()
        self.assertEqual(report['status'], 'INVALID')
        self.assertEqual(report['checks']['gzip'], 'fail')

    def test_concatenated_gzip_aggregate_budget_checked(self):
        first = self.tar_bytes()
        self.make(raw=gzip.compress(first) + gzip.compress(b'x' * 1024))
        self.assertEqual(self.audit(policy=replace(self.policy, max_uncompressed_bytes=len(first)))['status'], 'LIMIT')

    def test_in_place_source_metadata_change_detected(self):
        from backup_sentinel import engine
        path = self.make(); original = engine._check_gzip_stream
        def change(raw, policy):
            total = original(raw, policy)
            info = path.stat()
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
            return total
        with patch.object(engine, '_check_gzip_stream', change):
            report = engine.run_audit(str(self.backups), self.policy, str(self.scratch), NOW)
        self.assertEqual(report['status'], 'ERROR')
        self.assertEqual(report['reason'], 'source_changed')
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_source_path_replacement_detected(self):
        from backup_sentinel import engine
        path = self.make(); original = engine._check_gzip_stream
        replacement = self.root / 'replacement'
        replacement.write_bytes(path.read_bytes())
        def change(raw, policy):
            total = original(raw, policy)
            os.replace(replacement, path)
            return total
        with patch.object(engine, '_check_gzip_stream', change):
            report = engine.run_audit(str(self.backups), self.policy, str(self.scratch), NOW)
        self.assertEqual(report['status'], 'ERROR')
        self.assertEqual(report['reason'], 'source_changed')
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_exact_member_budget_passes_next_member_refused(self):
        self.make()
        self.assertEqual(self.audit(policy=replace(self.policy, max_members=1))['status'], 'OK')
        self.make(entries=[(MEMBER, self.database, tarfile.REGTYPE, ''), ('extra', b'x', tarfile.REGTYPE, '')])
        self.assertEqual(self.audit(policy=replace(self.policy, max_members=1))['status'], 'LIMIT')

    def test_mkdtemp_is_private_even_with_permissive_umask(self):
        old = os.umask(0o022)
        try:
            path = Path(tempfile.mkdtemp(prefix='permission-proof-', dir=self.root))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        finally:
            os.umask(old)

if __name__ == '__main__':
    unittest.main()
