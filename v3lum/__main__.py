"""Allow ``python -m v3lum``."""

import sys

from v3lum.cli import main

if __name__ == "__main__":
    sys.exit(main())
