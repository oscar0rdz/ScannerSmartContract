"""Helper to load the project-level `.env` file without relying on frame introspection."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"


def load_project_env(env_path: Optional[Path | str] = None) -> Path:
    """Load `.env` from the repo root (or from the optional `env_path`)."""
    target = Path(env_path) if env_path else DEFAULT_ENV_PATH
    load_dotenv(target)
    return target


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load the project .env before running a command")
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV_PATH, help="Path to .env file")
    parser.add_argument("command", nargs="+", help="Command to execute after loading the env")
    args = parser.parse_args()

    load_dotenv(args.env)

    if args.command:
        import subprocess

        subprocess.run(args.command, check=True)
