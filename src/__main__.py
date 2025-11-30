"""Allow running as: python -m src"""

import sys

from .vulnsort import main

if __name__ == "__main__":
    sys.exit(main())
