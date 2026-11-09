"""AuditPolicy: validated, immutable policy for Backup Sentinel audits.

Validation is strict by design: bool is rejected as an int,
floats (including NaN/infinity) are rejected outright, and every numeric
limit carries a sane ceiling so absurd/"excessive" limits are refused at
construction time.  Archive member names in a policy must already be in
canonical POSIX form: relative, no ``./`` or ``//`` segments, no trailing
slash, no ``..`` parts.  Backslashes, percent encodings and case are
ordinary text (POSIX member-name policy only).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence, Tuple, Union

MAX_POLICY_NAME_LEN = 256
MAX_POLICY_MEMBERS = 128
MAX_LIMIT_VALUE = 16 * 1024**3
MAX_MEMBERS_VALUE = 65536
MAX_TIMEOUT_SECONDS = 300
MAX_AGE_DAYS = 365

MemberList = Union[Sequence[str], Tuple[str, ...]]


def _check_int(name: str, value: object, lo: int, hi: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer" % name)
    if value < lo or value > hi:
        raise ValueError("%s out of range" % name)


def _check_member_name(name: object, where: str) -> str:
    if not isinstance(name, str):
        raise ValueError("%s member names must be strings" % where)
    if not name:
        raise ValueError("%s member name is empty" % where)
    if "\x00" in name:
        raise ValueError("%s member name is invalid" % where)
    if len(name) > MAX_POLICY_NAME_LEN:
        raise ValueError("%s member name too long" % where)
    if name.startswith("/"):
        raise ValueError("%s member names must be relative" % where)
    if name.endswith("/"):
        raise ValueError("%s member names must not end in '/'" % where)
    if name != name.replace("//", "/"):
        raise ValueError("%s member names must not contain '//'" % where)
    parts = name.split("/")
    if "." in parts or ".." in parts:
        raise ValueError("%s member names must be normalized" % where)
    return name


def _check_member_list(value: object, where: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("%s must be a list or tuple" % where)
    if len(value) > MAX_POLICY_MEMBERS:
        raise ValueError("too many %s members" % where)
    names = tuple(_check_member_name(n, where) for n in value)
    if len(set(names)) != len(names):
        raise ValueError("duplicate %s member" % where)
    return names


@dataclass(frozen=True)
class AuditPolicy:
    """Frozen, validated policy for one Backup Sentinel audit invocation."""

    prefix: str = "backup-"
    required_members: MemberList = (".hermes/state.db",)
    sqlite_members: MemberList = (".hermes/state.db",)
    max_age_days: int = 2
    max_compressed_bytes: int = 268435456
    max_uncompressed_bytes: int = 536870912
    max_db_bytes: int = 33554432
    max_members: int = 4096
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if not isinstance(self.prefix, str):
            raise ValueError("prefix must be a string")
        if not self.prefix:
            raise ValueError("prefix must not be empty")
        if "/" in self.prefix or "\x00" in self.prefix:
            raise ValueError("prefix must be a single literal path component")
        if len(self.prefix) > MAX_POLICY_NAME_LEN:
            raise ValueError("prefix too long")
        object.__setattr__(self, "required_members",
                           _check_member_list(self.required_members, "required"))
        object.__setattr__(self, "sqlite_members",
                           _check_member_list(self.sqlite_members, "sqlite"))
        _check_int("max_age_days", self.max_age_days, 0, MAX_AGE_DAYS)
        _check_int("max_compressed_bytes", self.max_compressed_bytes, 1, 8 * 1024**3)
        _check_int("max_uncompressed_bytes", self.max_uncompressed_bytes, 1, MAX_LIMIT_VALUE)
        _check_int("max_db_bytes", self.max_db_bytes, 1, 256 * 1024**2)
        _check_int("max_members", self.max_members, 1, MAX_MEMBERS_VALUE)
        _check_int("timeout_seconds", self.timeout_seconds, 1, MAX_TIMEOUT_SECONDS)

    @staticmethod
    def from_mapping(data: object) -> "AuditPolicy":
        """Coerce a plain mapping (e.g. a JSON request) into a validated policy."""
        if isinstance(data, AuditPolicy):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("policy must be an AuditPolicy or mapping")
        try:
            return AuditPolicy(**dict(data))
        except TypeError as exc:  # unknown/extra policy fields
            raise ValueError("invalid policy fields") from exc


__all__ = ["AuditPolicy"]