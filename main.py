#!/usr/bin/env python3
"""CF-Scanner Pro launcher - same as `python -m cfscan` or the `cfscan` command."""
import sys

if sys.version_info < (3, 8):
    sys.exit("CF-Scanner Pro needs Python 3.8 or newer.")

from cfscan.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
