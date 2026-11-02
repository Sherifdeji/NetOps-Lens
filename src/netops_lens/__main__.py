"""Package entry point: ``python -m netops_lens assess ...``."""

from __future__ import annotations

import sys

from netops_lens.cli import main


if __name__ == "__main__":
    sys.exit(main())
