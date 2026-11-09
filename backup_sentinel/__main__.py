"""Run with python -m backup_sentinel; never installs or activates Hermes plugins."""
from .cli import main

raise SystemExit(main())
