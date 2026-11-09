#!/bin/sh
set -eu
: "${TMPDIR:?Set TMPDIR to an existing private scratch directory}"
export PYTHONDONTWRITEBYTECODE=1
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
exec "${PYTHON:-python3}" -B -m unittest discover -s tests -p 'test_*.py' -v
