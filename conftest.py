"""Put the repo root on sys.path so `arch`, `prep`, ... import as packages.

The stage directories deliberately have no __init__.py: they are top-level
namespaces in this repo, not an installed distribution.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
