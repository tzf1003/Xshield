#!/usr/bin/env python3
"""Protection-effectiveness measurement. The code lives in tests/security-lab/effectiveness.

Usage:
  python3 scripts/measure_effectiveness.py score --observations FILE --decisions FILE [--truth FILE]
                                                 [--learned FILE] [--baseline FILE] [--out DIR]
  python3 scripts/measure_effectiveness.py [lab] [--mode quick|full] ...   (not built yet)
  python3 scripts/measure_effectiveness.py site (--decisions FILE | --control URL --site NAME)
                                                 --suite-results DIR_OR_ZIP [--truth FILE] [--objects FILE]
                                                 [--out DIR]

Exit status: 0 when every gate passes, 1 when a gate fails, 2 for a usage or environment error.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "security-lab"))

from effectiveness.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
