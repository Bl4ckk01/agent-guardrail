#!/usr/bin/env python3
"""Codex hook entry point."""

import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import guardrail_hook

if __name__ == "__main__":
    sys.exit(guardrail_hook.main(["hook", "--host", "codex"]))
