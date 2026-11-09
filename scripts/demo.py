"""Generate and audit synthetic backups; never searches for real backups."""
from __future__ import annotations
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def sqlite_bytes(folder: Path) -> bytes:
    path = folder / "synthetic-source.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE synthetic(id INTEGER PRIMARY KEY, note TEXT)")
    connection.execute("INSERT INTO synthetic(note) VALUES (?)", ("SYNTHETIC-NOT-A-REAL-SESSION",))
    connection.commit()
    connection.close()
    return path.read_bytes()


def archive(folder: Path, date: str, payload: bytes, missing=False) -> Path:
    folder.mkdir(mode=0o700)
    path = folder / ("backup-" + date + ".tar.gz")
    with tarfile.open(path, "w:gz") as stream:
        member = tarfile.TarInfo("unrelated.txt" if missing else ".hermes/state.db")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="NEW directory only; otherwise creates under TMPDIR")
    args = parser.parse_args(argv)
    if args.output_dir is None:
        base = Path(tempfile.mkdtemp(prefix="backup-sentinel-demo-", dir=os.environ["TMPDIR"]))
    else:
        base = args.output_dir.absolute()
        base.mkdir(mode=0o700, parents=False, exist_ok=False)
    scratch = base / "scratch"
    scratch.mkdir(mode=0o700)
    from backup_sentinel.model import AuditPolicy
    from backup_sentinel.supervisor import run_audit
    policy = AuditPolicy(prefix="backup-", required_members=(".hermes/state.db",), sqlite_members=(".hermes/state.db",))
    db = sqlite_bytes(base)
    good = archive(base / "good", "20261108", db)
    missing = archive(base / "missing-member", "20261108", db, missing=True)
    bad_db = archive(base / "bad-database", "20261108", b"SYNTHETIC-INVALID-SQLITE-CANARY")
    newest = base / "newest-corrupt"
    archive(newest, "20261107", db)
    (newest / "backup-20261108.tar.gz").write_bytes(b"SYNTHETIC-BROKEN-GZIP")
    cases = [("good archive + SQLite", good, "OK"), ("required file missing", missing, "INVALID"),
             ("corrupt SQLite", bad_db, "INVALID"), ("newest corrupt; older good exists", newest, "INVALID")]
    results = []
    for title, target, expected in cases:
        report = run_audit(target=str(target), policy=policy, scratch_root=str(scratch), now="2026-11-08")
        passed = report["status"] == expected and report["scratch_cleaned"] is True and report["restore_tested"] is False
        results.append({"case": title, "expected": expected, "matched": passed, "report": report})
        print(title + ": " + report["status"] + " (" + report["reason"] + ")")
    receipt = {"synthetic_only": True, "date_override": "2026-11-08", "cases": results,
        "scratch_empty": list(scratch.iterdir()) == [], "all_matched": all(row["matched"] for row in results)}
    path = base / "demo-results.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print("Synthetic receipt: " + str(path))
    print("Integrity checks are not a restore drill. No real backups were accessed.")
    return 0 if receipt["all_matched"] and receipt["scratch_empty"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
