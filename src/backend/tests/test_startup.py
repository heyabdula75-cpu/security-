import os
import subprocess
import sys
from pathlib import Path


def test_app_can_be_imported_from_workspace_root():
    repo_root = Path(__file__).resolve().parents[3]
    command = [sys.executable, "-c", "import app.main; print(app.main.app.title)"]

    result = subprocess.run(
        command,
        cwd=repo_root,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert "AI Supply Chain Security & SBOM Verification Platform" in result.stdout
