from pathlib import Path
import sys

repo_root = Path(__file__).resolve().parent.parent
backend_app_dir = repo_root / "src" / "backend" / "app"
backend_src_dir = repo_root / "src" / "backend"

for path in (backend_src_dir, backend_app_dir):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

package_dir = Path(__file__).resolve().parent
__path__ = [str(package_dir), str(backend_app_dir)] + list(__path__)
