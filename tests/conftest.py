"""pytest automagics"""
from typing import Any, Generator
import asyncio
import logging
from pathlib import Path

import pytest
from libadvian.logging import init_logging
from fastapi.testclient import TestClient
from fastapi_mail import FastMail
from arkia11nmodels.testhelpers import monkeysession, db_is_responsive, dockerdb  # pylint: disable=W0611

import arkia11napi.security
from arkia11napi.security import JWTHandler
import arkia11napi.mailer
from arkia11napi.api import APP

init_logging(logging.DEBUG)
LOGGER = logging.getLogger(__name__)
DATA_PATH = Path(__file__).parent / Path("data")


# pylint: disable=W0621


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """return event loop, made session scoped fixture to allow db connections to persists between tests"""
    loop = asyncio.get_event_loop()
    yield loop


@pytest.fixture(scope="session", autouse=True)
def jwt_env(monkeysession: Any) -> Generator[JWTHandler, None, None]:
    """Monkeypatch env with correct JWT keys and re-init the singleton"""
    monkeysession.setenv("JWT_PRIVKEY_PATH", str(DATA_PATH / "jwtRS256.key"))
    monkeysession.setenv("JWT_PUBKEY_PATH", str(DATA_PATH / "jwtRS256.pub"))
    monkeysession.setenv("JWT_PRIVKEY_PASS", "Disparate-Letdown-Pectin-Natural")  # pragma: allowlist secret
    monkeysession.setattr(arkia11napi.security, "HDL_SINGLETON", JWTHandler())
    singleton = JWTHandler.singleton()
    yield singleton


@pytest.fixture(scope="session", autouse=True)
def mailer_suppress_send(monkeysession: Any) -> Generator[FastMail, None, None]:
    """Make sure the mailer is configured and suppressed"""
    monkeysession.setenv("MAIL_FROM", "testsender@example.com")
    monkeysession.setenv("SUPPRESS_SEND", "1")
    monkeysession.setenv("MAIL_USERNAME", "")
    monkeysession.setenv("MAIL_PASSWORD", "")
    monkeysession.setenv("MAIL_PORT", "25")
    monkeysession.setenv("MAIL_SERVER", "localhost")
    monkeysession.setenv("MAIL_STARTTLS", "0")
    monkeysession.setenv("MAIL_SSL_TLS", "0")
    monkeysession.setenv("USE_CREDENTIALS", "0")
    singleton = arkia11napi.mailer.singleton()
    # Make sure
    singleton.config.MAIL_FROM = "testsender@example.com"
    singleton.config.SUPPRESS_SEND = 1
    yield singleton


@pytest.fixture
def client(jwt_env: JWTHandler, dockerdb: str) -> Generator[TestClient, None, None]:
    """Instantiated test client with superadmin privileges"""
    _ = dockerdb
    instance = TestClient(APP)
    # FIXME: issue superadmin privileges when we get there (and create a real user + role for those)
    token = jwt_env.issue({"dummy": True})
    LOGGER.debug("token={}".format(token))
    instance.headers.update({"Authorization": f"Bearer {token}"})
    yield instance


@pytest.fixture
def unauth_client(dockerdb: str) -> Generator[TestClient, None, None]:
    """Instantiated test client with no privileges"""
    _ = dockerdb
    instance = TestClient(APP)
    yield instance
