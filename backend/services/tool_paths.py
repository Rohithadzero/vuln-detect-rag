import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOLS_BIN = PROJECT_ROOT / "tools" / "bin"


def ensure_tools_on_path() -> None:
    wanted = [TOOLS_BIN, Path(sys.executable).parent]
    current = os.environ.get("PATH", "").split(os.pathsep)
    additions = [str(p) for p in wanted if p.is_dir() and str(p) not in current]
    if additions:
        os.environ["PATH"] = os.pathsep.join(additions + current)
