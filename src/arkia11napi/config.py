"""General configuration variables"""
from pathlib import Path

from starlette.config import Config

cfg = Config(".env")

STATIC_PATH: Path = cfg("STATIC_PATH", cast=Path, default=Path(__file__).parent / "staticfiles")
TEMPLATES_PATH: Path = cfg("TEMPLATES_PATH", cast=Path, default=Path(__file__).parent / "templates")
JWT_COOKIE_NAME: str = cfg("JWT_COOKIE_NAME", default="fi_pvarki_jwt")
JWT_COOKIE_DOMAIN: str = cfg("JWT_COOKIE_DOMAIN", default="pvarki.fi")
JWT_COOKIE_SECURE: bool = cfg("JWT_COOKIE_SECURE", default=True, cast=bool)
SUPERADMIN_ROLE_NAME = cfg("SUPERADMIN_ROLE_NAME", default="SuperAdmins")
