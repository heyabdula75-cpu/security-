import os
import sys
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "src" / "backend"


def main() -> int:
    os.chdir(BACKEND_DIR)
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(BACKEND_DIR))
    command = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
    completed = subprocess.run(command, cwd=BACKEND_DIR, env=env)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
