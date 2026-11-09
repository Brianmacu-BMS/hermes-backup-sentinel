"""Lexical Linux path checks. Trusted parents required; not a race-proof sandbox."""
import os
from pathlib import Path
import stat


def absolute_path(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("invalid_path")
    if any(ord(char) < 32 for char in value):
        raise ValueError("invalid_path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid_path")
    return path


def guard_path(value, *, missing_final=False):
    path = absolute_path(str(value))
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:], 1):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing_final and index == len(path.parts) - 1:
                return path
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError("path_alias_refused")
        if index < len(path.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("invalid_parent")
    return path


def private_scratch(value):
    path = guard_path(value)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("private_scratch_required")
    return path


def separate_paths(target, scratch):
    # A file target is separated from scratch by its containing backup directory.
    base = target if target.is_dir() else target.parent
    if scratch.is_relative_to(base) or base.is_relative_to(scratch):
        raise ValueError("scratch_target_overlap")
