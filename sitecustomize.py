import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent
backend_dir = repo_root / "src" / "backend"
backend_dir_str = str(backend_dir)

if backend_dir_str not in sys.path:
    sys.path.insert(0, backend_dir_str)
