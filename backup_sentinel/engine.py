"""Backup Sentinel audit engine (stdlib-only, in-process core).

``run_audit`` performs one full integrity audit of the selected ``.tar.gz``
backup: fresh-newest selection from filename dates, bounded gzip
verification to EOF (CRC/footer validated), tar structure inspection with
no general extraction, unique regular required members, and private
immutable SQLite integrity checks.  It never resolves, follows or displays
link targets, never prints member names/DB contents, and writes nothing
outside its own per-invocation private scratch directory.

Nonrequired links are opaque metadata only.  Required and SQLite members
must be unique regular files.  Credential-store names (``.env*``,
``auth.json``, ``credentials.json``, ``keys``, login stores, ...) are never
materialized, even when supplied as SQLite policy.  Source-file metadata
changes during the audit are detected via stat identity (not hashes).

Every outcome is a JSON-serializable report dict; this function never
raises.  Statuses: OK / MISSING / STALE / INVALID / LIMIT / ERROR.
"""

from __future__ import annotations

import datetime
import errno
import gzip
import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
import urllib.parse
import zlib

from .model import AuditPolicy
from .paths import guard_path, private_scratch

CHUNK_SIZE = 1024 * 1024
TAR_END_MARKER_BYTES = 2 * 512
SQLITE_HEADER = b"SQLite format 3\x00"
MAX_MEMBER_NAME_CHARS = 1024
_SQLITE_BUDGET_FRACTION = 0.8  # of policy timeout, leaves room to emit report

_GZIP_ERRORS = (gzip.BadGzipFile, EOFError, zlib.error)
_ARCHIVE_ERRORS = _GZIP_ERRORS + (tarfile.TarError, ValueError)

_STATUSES = ("OK", "MISSING", "STALE", "INVALID", "LIMIT", "ERROR")
_CHECK_STATUSES = ("ok", "fail", "limit", "not_run", "not_requested", "stale")

_DATE_STR = "%Y-%m-%d"
_DATE_FILE_RE = None  # built lazily: 8-digit date inside the filename

_CREDENTIAL_BASENAMES = frozenset({
    "auth.json", "credentials", "credentials.json", "credential", "secret",
    "secrets", "secrets.json", "key", "keys", "keyring", "keychain",
    "login", "login.json", "login-store", "login data", ".netrc", ".pgpass",
    "passwd", "shadow", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "known_hosts", "authorized_keys",
})
_CREDENTIAL_SUBSTRINGS = ("credential", "password", "secret", "token")


class _Stop(Exception):
    """Terminal audit outcome carrying a generic machine-readable reason."""

    def __init__(self, status, reason, checks=None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.checks = checks or {}


def _initial_checks(policy):
    return {
        "freshness": "not_run",
        "gzip": "not_run",
        "tar": "not_run",
        "required": "not_run" if policy.required_members else "not_requested",
        "sqlite": "not_requested" if not policy.sqlite_members else "not_run",
    }


def _report(status, reason, checks, coverage, selected_date, scratch_cleaned):
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "checks": checks,
        "coverage": coverage,
        "restore_tested": False,
        "scratch_cleaned": scratch_cleaned,
        "selected_date": selected_date,
    }


def run_audit(target, policy, scratch_root, now=None):
    """Audit one backup per ``policy``; returns the report dict (never raises)."""
    checks = _initial_checks(policy)
    coverage = "archive_and_sqlite" if policy.sqlite_members else "archive_integrity_only"
    status, reason = "ERROR", "internal_error"
    selected_date = None
    scratch_cleaned = True
    private = None
    try:
        now_date = _parse_now(now)
        _check_scratch_root(scratch_root)
        private = _make_private_scratch(scratch_root)
        date, path = _select_target(target, policy, now_date)
        selected_date = date.isoformat()
        checks["freshness"] = "ok"
        _check_freshness(date, now_date, policy, checks)
        _audit_archive(path, policy, private, checks)
        status, reason = "OK", "ok"
    except _Stop as stop:
        status, reason = stop.status, stop.reason
        for key, value in stop.checks.items():
            checks[key] = value
    except OSError:
        status, reason = "ERROR", "io_error"
    except Exception:
        status, reason = "ERROR", "internal_error"
    finally:
        if private is not None:
            try:
                shutil.rmtree(private)
            except OSError:
                scratch_cleaned = False
            else:
                scratch_cleaned = not os.path.lexists(private)
            if not scratch_cleaned:
                status, reason = "ERROR", "scratch_cleanup_failed"
    return _report(status, reason, checks, coverage, selected_date, scratch_cleaned)


# --- time and path handling --------------------------------------------------

def _parse_now(now):
    if now is None:
        return datetime.date.today()
    if isinstance(now, datetime.date) and not isinstance(now, datetime.datetime):
        return now
    if not isinstance(now, str):
        raise _Stop("ERROR", "invalid_now")
    try:
        return datetime.datetime.strptime(now, _DATE_STR).date()
    except ValueError:
        raise _Stop("ERROR", "invalid_now") from None


def _check_path_ancestors(path, what):
    """Refuse lexical ancestor symlinks/reparse entries before resolution."""
    try:
        return str(guard_path(path, missing_final=True))
    except (ValueError, OSError, TypeError):
        raise _Stop("ERROR", what + "_path_refused") from None


def _check_scratch_root(scratch_root):
    try:
        private_scratch(scratch_root)
    except (ValueError, OSError, TypeError):
        raise _Stop("ERROR", "private_scratch_required") from None



def _make_private_scratch(scratch_root):
    try:
        private = tempfile.mkdtemp(prefix="backup-sentinel-", dir=scratch_root)
        os.chmod(private, 0o700)
    except OSError:
        raise _Stop("ERROR", "scratch_creation_failed") from None
    return private


# --- selection ---------------------------------------------------------------

def _parse_candidate_name(name, prefix):
    """Return None (not a candidate), 'blocked', or the archive date."""
    if not name.startswith(prefix):
        return None
    suffix = name[len(prefix):]
    if len(suffix) != 15 or not suffix.endswith(".tar.gz"):
        return None
    digits = suffix[:8]
    if not digits.isascii() or not digits.isdigit():
        return None
    try:
        return datetime.date(int(digits[0:4]), int(digits[4:6]), int(digits[6:8]))
    except ValueError:
        return "blocked"


def _select_target(target, policy, now_date):
    """Pick the newest valid candidate; return (date, absolute path)."""
    path = _check_path_ancestors(target, "target")
    base = os.path.basename(path)
    if base == "":
        raise _Stop("ERROR", "target_invalid")
    try:
        st = os.lstat(path)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise _Stop("ERROR", "target_missing") from None
        raise _Stop("ERROR", "target_invalid") from None
    if stat.S_ISLNK(st.st_mode):
        raise _Stop("ERROR", "target_symlink")
    if stat.S_ISDIR(st.st_mode):
        return _select_from_dir(path, policy, now_date)
    if not stat.S_ISREG(st.st_mode):
        raise _Stop("ERROR", "target_invalid_type")
    date = _parse_candidate_name(base, policy.prefix)
    if date is None:
        raise _Stop("MISSING", "archive_missing")
    if date == "blocked":
        raise _Stop("INVALID", "candidate_impossible_date", {"freshness": "fail"})
    if date > now_date:
        raise _Stop("INVALID", "candidate_future_date", {"freshness": "fail"})
    return date, path


def _select_from_dir(dirpath, policy, now_date):
    best = None
    blocking = None
    try:
        with os.scandir(dirpath) as entries:
            for scanned, entry in enumerate(entries, 1):
                if scanned > policy.max_members:
                    raise _Stop("LIMIT", "directory_entry_limit")
                date = _parse_candidate_name(entry.name, policy.prefix)
                if date is None:
                    continue
                if date == "blocked":
                    blocking = blocking or "candidate_impossible_date"
                    continue
                if date > now_date:
                    blocking = blocking or "candidate_future_date"
                    continue
                try:
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        blocking = blocking or "candidate_not_regular"
                        continue
                except OSError:
                    raise _Stop("ERROR", "scan_failed") from None
                if best is None or date > best[0]:
                    best = (date, os.path.join(dirpath, entry.name))
    except OSError:
        raise _Stop("ERROR", "scan_failed") from None
    if blocking is not None:
        raise _Stop("INVALID", blocking, {"freshness": "fail"})
    if best is None:
        raise _Stop("MISSING", "archive_missing")
    return best


def _check_freshness(date, now_date, policy, checks):
    age = (now_date - date).days
    if age > policy.max_age_days:
        raise _Stop("STALE", "archive_stale", {"freshness": "stale"})


# --- archive validation ------------------------------------------------------

def _check_gzip_stream(raw, policy):
    total = 0
    try:
        with gzip.GzipFile(fileobj=raw, mode="rb") as gz:
            while True:
                chunk = gz.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > policy.max_uncompressed_bytes:
                    raise _Stop("LIMIT", "uncompressed_size_limit", {"gzip": "limit"})
    except _Stop:
        raise
    except _GZIP_ERRORS:
        raise _Stop("INVALID", "gzip_invalid", {"gzip": "fail"}) from None
    except OSError:
        raise _Stop("ERROR", "io_error") from None
    if total == 0:
        raise _Stop("INVALID", "gzip_empty", {"gzip": "fail"})
    return total


def _normalize_member_name(name):
    if "\x00" in name:
        raise _Stop("INVALID", "member_name_invalid", {"tar": "fail"})
    if name.startswith("/"):
        raise _Stop("INVALID", "member_absolute_path", {"tar": "fail"})
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise _Stop("INVALID", "member_traversal", {"tar": "fail"})
    return "/".join(parts)


def _inspect_tar(tf, gz, total, policy):
    seen = {}
    count = 0
    while True:
        member = tf.next()
        if member is None:
            break
        count += 1
        if count > policy.max_members:
            raise _Stop("LIMIT", "member_count_limit", {"tar": "limit"})
        if len(member.name) > MAX_MEMBER_NAME_CHARS:
            raise _Stop("INVALID", "member_name_too_long", {"tar": "fail"})
        key = _normalize_member_name(member.name)
        if member.issparse():
            raise _Stop("INVALID", "sparse_member", {"tar": "fail"})
        if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
            raise _Stop("INVALID", "special_member", {"tar": "fail"})
        if key == "" and not member.isdir():
            raise _Stop("INVALID", "member_name_invalid", {"tar": "fail"})
        if key in seen:
            raise _Stop("INVALID", "duplicate_member", {"tar": "fail"})
        if member.size < 0 or member.offset_data + member.size > total:
            # Negative or beyond-stream sizes are unsafe metadata ("invalid-size").
            reason = "invalid_member_size" if member.size < 0 else "archive_truncated"
            raise _Stop("INVALID", reason, {"tar": "fail"})
        seen[key] = member

    # Termination: everything after the last member header must be the tar
    # zero end-of-archive marker (>= 2 zero blocks); tarfile silently stops
    # at a damaged header otherwise.
    if tf.offset > total:
        raise _Stop("INVALID", "archive_truncated", {"tar": "fail"})
    gz.seek(tf.offset)
    trailing = 0
    while True:
        chunk = gz.read(CHUNK_SIZE)
        if not chunk:
            break
        if chunk.strip(b"\x00"):
            raise _Stop("INVALID", "trailing_garbage", {"tar": "fail"})
        trailing += len(chunk)
    if trailing < TAR_END_MARKER_BYTES:
        raise _Stop("INVALID", "missing_end_marker", {"tar": "fail"})
    return seen


def _check_required(seen, policy):
    for name in policy.required_members:
        member = seen.get(name)
        if member is None:
            raise _Stop("INVALID", "required_member_missing", {"required": "fail"})
        if not member.isreg():
            raise _Stop("INVALID", "required_member_not_regular", {"required": "fail"})


class _BoundedTarInfo(tarfile.TarInfo):
    """Refuse oversized extension headers before stdlib _safe_read allocates."""
    def _proc_member(self, archive):
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise _Stop("INVALID", "sparse_member", {"tar": "fail"})
        extensions = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                      tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
        if self.type in extensions:
            total = getattr(archive, '_sentinel_metadata_bytes', 0) + self.size
            if self.size < 0:
                raise _Stop("INVALID", "invalid_metadata_size", {"tar": "fail"})
            if total > CHUNK_SIZE:
                raise _Stop("LIMIT", "metadata_read_limit", {"tar": "limit"})
            archive._sentinel_metadata_bytes = total
        return super()._proc_member(archive)


class _BoundedMetadata:
    """tarfile may otherwise allocate an entire hostile PAX/GNU extension."""
    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        if size < 0 or size > CHUNK_SIZE:
            raise _Stop("LIMIT", "metadata_read_limit", {"tar": "limit"})
        return self.stream.read(size)

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _audit_archive(path, policy, private, checks):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO):
            raise _Stop("INVALID", "candidate_not_regular") from None
        raise _Stop("ERROR", "open_failed") from None
    with os.fdopen(fd, "rb") as raw:
        try:
            before = os.fstat(raw.fileno())
        except OSError:
            raise _Stop("ERROR", "io_error") from None
        if not stat.S_ISREG(before.st_mode):
            raise _Stop("INVALID", "candidate_not_regular")
        if before.st_size > policy.max_compressed_bytes:
            raise _Stop("LIMIT", "compressed_size_limit", {"gzip": "limit"})

        total = _check_gzip_stream(raw, policy)
        checks["gzip"] = "ok"

        try:
            raw.seek(0)
            with gzip.GzipFile(fileobj=raw, mode="rb") as gz:
                with tarfile.open(fileobj=_BoundedMetadata(gz), mode="r:", tarinfo=_BoundedTarInfo) as tf:
                    seen = _inspect_tar(tf, gz, total, policy)
                    checks["tar"] = "ok"
                    _check_required(seen, policy)
                    checks["required"] = "ok" if policy.required_members else "not_requested"
                    _check_sqlite(tf, seen, policy, private, checks)
        except _Stop:
            raise
        except _ARCHIVE_ERRORS:
            raise _Stop("INVALID", "tar_invalid", {"tar": "fail"}) from None
        except OSError:
            raise _Stop("ERROR", "io_error") from None

        try:
            after = os.fstat(raw.fileno())
        except OSError:
            raise _Stop("ERROR", "io_error") from None
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        named = os.stat(path, follow_symlinks=False)
        if any(getattr(before, f) != getattr(after, f) or getattr(before, f) != getattr(named, f) for f in identity):
            raise _Stop("ERROR", "source_changed")


# --- SQLite verification -----------------------------------------------------

def _is_credential_name(name):
    parts = name.lower().split("/")
    if any(part in _CREDENTIAL_BASENAMES or part in {'.ssh', '.aws', '.gnupg', 'keychains'} or part.startswith('.env') for part in parts):
        return True
    base = parts[-1]
    if base.startswith(".env"):
        return True
    if base in _CREDENTIAL_BASENAMES:
        return True
    return any(sub in base for sub in _CREDENTIAL_SUBSTRINGS)


def _deadline_handler(deadline):
    def handler():
        return time.monotonic() >= deadline
    return handler


def _check_sqlite(tf, seen, policy, private, checks):
    if not policy.sqlite_members:
        checks["sqlite"] = "not_requested"
        return
    deadline = time.monotonic() + max(0.05, policy.timeout_seconds * _SQLITE_BUDGET_FRACTION)
    for index, name in enumerate(policy.sqlite_members):
        if _is_credential_name(name):
            raise _Stop("ERROR", "credential_member_denied", {"sqlite": "fail"})
        member = seen.get(name)
        if member is None:
            raise _Stop("INVALID", "sqlite_member_missing", {"sqlite": "fail"})
        if not member.isreg():
            raise _Stop("INVALID", "sqlite_member_not_regular", {"sqlite": "fail"})
        if member.size > policy.max_db_bytes:
            raise _Stop("LIMIT", "db_size_limit", {"sqlite": "limit"})
        if member.size < len(SQLITE_HEADER):
            raise _Stop("INVALID", "sqlite_member_not_sqlite", {"sqlite": "fail"})
        db_path = os.path.join(private, "sqlite-%d.db" % index)
        _materialize(tf, member, db_path, deadline)
        _sqlite_checks(db_path, deadline)
    checks["sqlite"] = "ok"


def _materialize(tf, member, db_path, deadline):
    src = tf.extractfile(member)
    if src is None:
        raise _Stop("INVALID", "sqlite_member_unreadable", {"sqlite": "fail"})
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(db_path, flags, 0o600)
    except OSError:
        raise _Stop("ERROR", "scratch_write_failed") from None
    with os.fdopen(fd, "wb") as dst:
        try:
            os.fchmod(dst.fileno(), 0o600)
        except OSError:
            raise _Stop("ERROR", "scratch_write_failed") from None
        remaining = member.size
        first = src.read(len(SQLITE_HEADER))
        if first != SQLITE_HEADER:
            raise _Stop("INVALID", "sqlite_member_not_sqlite", {"sqlite": "fail"})
        chunk = first
        while True:
            try:
                dst.write(chunk)
            except OSError:
                raise _Stop("ERROR", "scratch_write_failed") from None
            remaining -= len(chunk)
            if remaining <= 0:
                break
            if time.monotonic() >= deadline:
                raise _Stop("LIMIT", "sqlite_check_time_limit", {"sqlite": "limit"})
            chunk = src.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise _Stop("INVALID", "sqlite_member_truncated", {"sqlite": "fail"})


def _sqlite_checks(db_path, deadline):
    uri = "file:" + urllib.parse.quote(db_path) + "?mode=ro&immutable=1"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.set_progress_handler(_deadline_handler(deadline), 500)
        if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise _Stop("INVALID", "sqlite_integrity_failed", {"sqlite": "fail"})
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _Stop("INVALID", "sqlite_foreign_key_failed", {"sqlite": "fail"})
    except _Stop:
        raise
    except sqlite3.Error:
        if time.monotonic() >= deadline:
            raise _Stop("LIMIT", "sqlite_check_time_limit", {"sqlite": "limit"}) from None
        raise _Stop("INVALID", "sqlite_invalid", {"sqlite": "fail"}) from None
    finally:
        if conn is not None:
            try:
                conn.set_progress_handler(None, 0)
            except sqlite3.Error:
                pass
            conn.close()
        try:
            os.unlink(db_path)
        except OSError:
            pass  # authoritative cleanup is the private-dir removal


__all__ = ["run_audit"]