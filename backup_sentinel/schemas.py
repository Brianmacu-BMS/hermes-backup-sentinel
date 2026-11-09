"""Operator-only configuration. Model arguments cannot widen this policy."""
from .model import AuditPolicy
from .paths import absolute_path

ALLOWED_KEYS = frozenset({'allowed_roots', 'scratch_dir', 'prefix', 'required_members', 'sqlite_members',
    'max_age_days', 'max_compressed_bytes', 'max_uncompressed_bytes', 'max_db_bytes', 'max_members', 'timeout_seconds'})
LIMITS = {'max_age_days': (0, 365), 'max_compressed_bytes': (1, 8 * 1024**3),
    'max_uncompressed_bytes': (1, 16 * 1024**3), 'max_db_bytes': (1, 256 * 1024**2),
    'max_members': (1, 65536), 'timeout_seconds': (1, 300)}
DEFAULTS = {'prefix': 'backup-', 'required_members': ['.hermes/state.db'], 'sqlite_members': ['.hermes/state.db'],
    'max_age_days': 2, 'max_compressed_bytes': 268435456, 'max_uncompressed_bytes': 536870912,
    'max_db_bytes': 33554432, 'max_members': 4096, 'timeout_seconds': 30}

class ConfigValidationError(ValueError):
    pass


def validate_numeric(name, value, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise ConfigValidationError('invalid_numeric_policy')
    return value


def validate_policy_config(raw):
    if type(raw) is not dict or set(raw) - ALLOWED_KEYS:
        raise ConfigValidationError('invalid_configuration')
    roots = raw.get('allowed_roots')
    if type(roots) is not list or not 1 <= len(roots) <= 32:
        raise ConfigValidationError('explicit_roots_required')
    try:
        cleaned_roots = [str(absolute_path(value)) for value in roots]
        if '/' in cleaned_roots:
            raise ValueError('filesystem_root_refused')
        scratch = str(absolute_path(raw.get('scratch_dir')))
        values = {}
        for name in ('prefix', 'required_members', 'sqlite_members'):
            values[name] = raw.get(name, DEFAULTS[name])
        for name, (low, high) in LIMITS.items():
            values[name] = validate_numeric(name, raw.get(name, DEFAULTS[name]), low, high)
        policy = AuditPolicy(**values)
    except (ValueError, TypeError, OSError):
        raise ConfigValidationError('invalid_configuration') from None
    result = {name: getattr(policy, name) for name in DEFAULTS}
    result['required_members'] = list(policy.required_members)
    result['sqlite_members'] = list(policy.sqlite_members)
    return {**result, 'allowed_roots': cleaned_roots, 'scratch_dir': scratch}
