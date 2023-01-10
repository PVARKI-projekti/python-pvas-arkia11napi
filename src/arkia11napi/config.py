"""General configuration variables"""
from pathlib import Path

from starlette.config import Config

cfg = Config(".env")

STATIC_PATH: Path = cfg("STATIC_PATH", cast=Path, default=Path(__file__).parent / "staticfiles")
TEMPLATES_PATH: Path = cfg("TEMPLATES_PATH", cast=Path, default=Path(__file__).parent / "templates")
