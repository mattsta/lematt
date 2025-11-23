"""Entry point for running lematt as a module.

Allows running lematt with: python -m lematt
or with uv: uv run lematt
"""

import sys

from lematt.cli import main

if __name__ == "__main__":
    sys.exit(main())
