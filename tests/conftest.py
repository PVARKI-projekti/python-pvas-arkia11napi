"""pytest automagics"""
from typing import Any, Generator
import logging
from pathlib import Path

import pytest
from libadvian.logging import init_logging

import arkia11napi.security
from arkia11napi.security import JWTHandler


init_logging(logging.DEBUG)
LOGGER = logging.getLogger(__name__)
DATA_PATH = Path(__file__).parent / Path("data")


# pylint: disable=W0621


# FIXME: should be moved to libadvian.testhelpers
@pytest.fixture(scope="session")
def monkeysession() -> Any:  # while we wait for the type come out of _pytest
    """session scoped monkeypatcher"""
    with pytest.MonkeyPatch.context() as mpatch:
        yield mpatch


@pytest.fixture(scope="session", autouse=True)
def jwt_env(monkeysession: Any) -> Generator[JWTHandler, None, None]:
    """Monkeypatch env with correct JWT keys and re-init the singleton"""
    monkeysession.setenv("JWT_PRIVKEY_PATH", str(DATA_PATH / "jwtRS256.key"))
    monkeysession.setenv("JWT_PUBKEY_PATH", str(DATA_PATH / "jwtRS256.pub"))
    monkeysession.setenv("JWT_PRIVKEY_PASS", "Disparate-Letdown-Pectin-Natural")  # pragma: allowlist secret
    monkeysession.setattr(arkia11napi.security, "HDL_SINGLETON", JWTHandler())
    singleton = JWTHandler.singleton()
    yield singleton
