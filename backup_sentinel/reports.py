"""Strict inert report transport contract; no arbitrary text or extra fields."""
from datetime import date
import json
import re

EXIT_CODES = {'OK': 0, 'MISSING': 1, 'STALE': 1, 'INVALID': 2, 'LIMIT': 3, 'ERROR': 4, 'TIMEOUT': 5}
CHECKS = ('freshness', 'gzip', 'tar', 'required', 'sqlite')
KEYS = {'schema_version', 'status', 'reason', 'checks', 'coverage', 'restore_tested', 'scratch_cleaned', 'selected_date'}
CHECK_VALUES = {'ok', 'fail', 'limit', 'not_run', 'not_requested', 'stale'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def load_report(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > 16384:
        raise ValueError('invalid_report')
    value = json.loads(text, object_pairs_hook=unique_object)
    validate_report(value)
    return value


def validate_report(value):
    if type(value) is not dict or set(value) != KEYS:
        raise ValueError('invalid_report')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('invalid_report')
    if type(value['status']) is not str or value['status'] not in EXIT_CODES:
        raise ValueError('invalid_report')
    if not isinstance(value['reason'], str) or not re.fullmatch('[a-z0-9_]{1,120}', value['reason']):
        raise ValueError('invalid_report')
    checks = value['checks']
    if type(checks) is not dict or set(checks) != set(CHECKS):
        raise ValueError('invalid_report')
    if any(type(item) is not str or item not in CHECK_VALUES for item in checks.values()):
        raise ValueError('invalid_report')
    if value['coverage'] not in ('archive_integrity_only', 'archive_and_sqlite'):
        raise ValueError('invalid_report')
    if value['restore_tested'] is not False or type(value['scratch_cleaned']) is not bool:
        raise ValueError('invalid_report')
    selected = value['selected_date']
    if selected is not None:
        if type(selected) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', selected):
            raise ValueError('invalid_report')
        date.fromisoformat(selected)
    if value['status'] == 'OK':
        if selected is None or not value['scratch_cleaned'] or any(checks[k] != 'ok' for k in ('freshness', 'gzip', 'tar')):
            raise ValueError('invalid_report')
        if checks['required'] not in ('ok', 'not_requested'):
            raise ValueError('invalid_report')
        expected = 'ok' if value['coverage'] == 'archive_and_sqlite' else 'not_requested'
        if checks['sqlite'] != expected:
            raise ValueError('invalid_report')
    return value
