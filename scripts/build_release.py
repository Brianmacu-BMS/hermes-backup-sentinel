"""Build a deterministic reviewable-source ZIP; never publishes or installs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXED = {"__init__.py", "plugin.yaml", "README.md", "LICENSE", "PROVENANCE.md", "SECURITY.md", "CHANGELOG.md", ".gitignore", ".gitattributes"}


def selected_sources():
    selected = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        parts = relative.parts
        if any(piece in {".git", "__pycache__", ".venv", "artifacts"} for piece in parts):
            continue
        if path.is_symlink():
            raise ValueError("symlink in source tree")
        if not path.is_file():
            continue
        name = relative.as_posix()
        include = name in FIXED
        include |= parts[0] == "backup_sentinel" and path.suffix == ".py"
        include |= parts[0] == "tests" and path.suffix == ".py" and (
            path.name.startswith('test_') or path.name == 'native_installed_acceptance.py')
        include |= parts[0] == "skills" and path.suffix == ".md"
        include |= parts[0] == "scripts" and path.suffix in {".py", ".sh"}
        include |= len(parts) > 2 and parts[:2] == (".github", "workflows") and path.suffix in {".yml", ".yaml"}
        if include:
            selected.append((name, path.read_bytes()))
    return selected


def info(name):
    result = zipfile.ZipInfo("backup-sentinel/" + name, date_time=(1980, 1, 1, 0, 0, 0))
    result.create_system = 3
    result.external_attr = ((stat.S_IFREG | (0o755 if name.endswith(".sh") else 0o644)) << 16)
    result.compress_type = zipfile.ZIP_DEFLATED
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="NEW ZIP path outside source tree")
    args = parser.parse_args(argv)
    destination = args.output.absolute()
    if destination.is_relative_to(ROOT) or destination.suffix != ".zip":
        parser.error("output must be a new .zip outside the source tree")
    sources = selected_sources()
    manifest = {"schema_version": 1, "version": "0.1.0", "files": {
        name: {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()} for name, body in sources}}
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as raw:
        with zipfile.ZipFile(raw, "w") as archive:
            for name, body in sources:
                archive.writestr(info(name), body)
            archive.writestr(info("SOURCE-MANIFEST.json"), manifest_bytes)
    # Independently reopen the exact distribution and bind each member to source bytes.
    with zipfile.ZipFile(destination) as archive:
        expected = {"backup-sentinel/" + name for name, _ in sources} | {"backup-sentinel/SOURCE-MANIFEST.json"}
        if set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
            raise ValueError("release membership mismatch")
        for name, body in sources:
            if archive.read("backup-sentinel/" + name) != body:
                raise ValueError("release byte mismatch")
        if archive.testzip() is not None:
            raise ValueError("release CRC mismatch")
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    print(json.dumps({"archive": str(destination), "sha256": digest, "source_files": len(sources), "reopened_and_verified": True}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
