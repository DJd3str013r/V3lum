#!/usr/bin/env python3
"""Convenience launcher: ``python v3lum.py <command>`` from a source checkout."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from v3lum.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
