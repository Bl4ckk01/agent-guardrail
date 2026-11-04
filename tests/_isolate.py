"""Point the guardrail's state, audit log and backups at a throw-away directory.

Import this before check_action / guardrail_hook: the hook reads GUARDRAIL_HOME once, at import time.
Without it the tests append thousands of fake entries to the user's real ~/.guardrail/guardrail.log,
which skews /guardrail report and /guardrail why.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

_PREFIX = "guardrail-tests-"

# Rules about policy.yaml, install.py... depend on the working directory (only the guardrail's own copies
# are protected), so the tests always run from the repository root, wherever they are launched from.
os.chdir(Path(__file__).resolve().parent.parent)

if not os.environ.get("GUARDRAIL_TESTS_ISOLATED"):
    _home = tempfile.mkdtemp(prefix=_PREFIX)
    os.environ["GUARDRAIL_HOME"] = _home
    os.environ["GUARDRAIL_TESTS_ISOLATED"] = "1"
    atexit.register(shutil.rmtree, _home, ignore_errors=True)

TEST_HOME = os.environ["GUARDRAIL_HOME"]
