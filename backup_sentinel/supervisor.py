"""Bounded fixed-worker process supervision; no shell, preexec hook or inherited secrets."""
from __future__ import annotations
import datetime
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from .model import AuditPolicy
from .paths import guard_path, private_scratch, separate_paths
from .reports import CHECKS, load_report

_WORKER_ARGV = (sys.executable, '-I', '-B', str(Path(__file__).parent / 'worker.py'))
_MAX_REQUEST_BYTES = 65536
_MAX_RESULT_BYTES = 16384
_MAX_STDERR_BYTES = 16384


def _error_report(reason, status='ERROR'):
    return {'schema_version': 1, 'status': status, 'reason': reason,
        'checks': {key: 'not_run' for key in CHECKS}, 'coverage': 'archive_integrity_only',
        'restore_tested': False, 'scratch_cleaned': True, 'selected_date': None}


def _normalize_now(now):
    if now is None:return datetime.date.today().isoformat()
    if isinstance(now, datetime.datetime):raise ValueError('invalid_now')
    if isinstance(now, datetime.date):return now.isoformat()
    if type(now) is not str or len(now) != 10:raise ValueError('invalid_now')
    parsed = datetime.date.fromisoformat(now)
    if parsed.isoformat() != now:raise ValueError('invalid_now')
    return now


def run_audit(target, policy, scratch_root, now=None):
    private = None
    report = _error_report('invalid_request')
    try:
        policy = AuditPolicy.from_mapping(policy)
        chosen = guard_path(target, missing_final=True)
        scratch = private_scratch(scratch_root)
        separate_paths(chosen, scratch)
        now = _normalize_now(now)
        request = {'target': str(chosen), 'policy': {name: getattr(policy, name) for name in policy.__dataclass_fields__}, 'now': now}
        private = tempfile.mkdtemp(prefix='backup-sentinel-', dir=scratch)
        os.chmod(private, 0o700)
        request['scratch'] = private
        payload = json.dumps(request, sort_keys=True, allow_nan=False).encode()
        if len(payload) > _MAX_REQUEST_BYTES:
            report = _error_report('request_too_large')
        else:
            report = _run_worker(payload, policy.timeout_seconds)
    except (ValueError, TypeError, OSError):
        report = _error_report('invalid_request_or_path')
    except Exception:
        report = _error_report('internal_error')
    finally:
        if private is not None:
            cleaned = _cleanup_private(private)
            report['scratch_cleaned'] = cleaned
            if not cleaned:
                report = _error_report('cleanup_failed')
                report['scratch_cleaned'] = False
    return report


def _cleanup_private(private):
    try:shutil.rmtree(private)
    except OSError:return False
    return not os.path.lexists(private)


def _kill_group(proc):
    try:os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:pass
    except OSError:proc.kill()
    proc.wait(timeout=3)


def _run_worker(payload, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    try:
        proc = subprocess.Popen(_WORKER_ARGV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': os.defpath}, cwd=str(Path(__file__).parent.parent),
            start_new_session=True, close_fds=True, bufsize=0)
    except OSError:return _error_report('worker_spawn_failed')
    output, errors = bytearray(), bytearray()
    sent = 0
    stop = None
    with selectors.DefaultSelector() as selector:
        for stream, role in ((proc.stdin, 'input'), (proc.stdout, 'output'), (proc.stderr, 'error')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_WRITE if role == 'input' else selectors.EVENT_READ, role)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    stop = _error_report('worker_timeout', 'TIMEOUT'); break
                for key, _ in selector.select(min(0.05, remaining)):
                    stream, role = key.fileobj, key.data
                    if role == 'input':
                        try:sent += os.write(stream.fileno(), payload[sent:sent + 4096])
                        except BrokenPipeError:sent = len(payload)
                        if sent == len(payload):selector.unregister(stream); stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 4096)
                        if not chunk:selector.unregister(stream); stream.close(); continue
                        buffer, cap = (output, _MAX_RESULT_BYTES) if role == 'output' else (errors, _MAX_STDERR_BYTES)
                        if len(buffer) + len(chunk) > cap:
                            stop = _error_report('worker_output_limit'); break
                        buffer.extend(chunk)
                if stop is not None:break
            if stop is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:stop = _error_report('worker_timeout', 'TIMEOUT')
                else:
                    try:proc.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:stop = _error_report('worker_timeout', 'TIMEOUT')
        except (OSError, ValueError):
            stop = _error_report('worker_transport_failed')
        finally:
            if proc.poll() is None or stop is not None:
                _kill_group(proc)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if not stream.closed:stream.close()
    if stop is not None:return stop
    if proc.returncode != 0:
        if proc.returncode in (-signal.SIGXCPU, -signal.SIGXFSZ):return _error_report('worker_resource_limit', 'LIMIT')
        return _error_report('worker_failed')
    try:
        report = load_report(output.decode('utf-8'))
        if report['status'] == 'TIMEOUT':raise ValueError('parent_owned_status')
        return report
    except (ValueError, TypeError, UnicodeError, RecursionError):return _error_report('worker_report_invalid')
