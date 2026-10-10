"""Entry point for running lematt as a module.

Run lematt with `uv run lematt`; the systemd unit runs `python -m lematt`
with the project environment's Python.
"""

import sys

from lematt.cli import main

if __name__ == "__main__":
    sys.exit(main())
