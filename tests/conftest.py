"""pytest automagics"""
from typing import Any, Generator, AsyncGenerator, List, cast
import asyncio
import logging
from pathlib import Path
import random

import pytest
import pytest_asyncio
from libadvian.binpackers import uuid_to_b64
from libadvian.logging import init_logging
from async_asgi_testclient import TestClient
from fastapi_mail import FastMail
import sqlalchemy
from asyncpg.exceptions import DuplicateSchemaError
from arkia11nmodels import models
from arkia11nmodels.testhelpers import monkeysession  # pylint: disable=W0611 ; # false positive
from arkia11nmodels.models.role import UserRole
from arkia11nmodels.models import User, Role


import arkia11napi.security
from arkia11napi.security import JWTHandler
import arkia11napi.mailer
from arkia11napi.api import APP, WRAPPER

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
    monkeysession.setenv("JWT_COOKIE_SECURE", "0")
    monkeysession.setenv("JWT_COOKIE_DOMAIN", "")
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


async def get_or_create_user(email: str) -> models.User:
    """Get by email or create"""
    user = await models.User.query.where(models.User.email == email).gino.first()
    if user:
        return cast(models.User, user)
    # no match, create
    user = models.User(email=email)
    await user.create()
    user = await models.User.get(user.pk)
    return cast(models.User, user)


@pytest_asyncio.fixture(scope="session")
async def client(jwt_env: JWTHandler, dockerdb: str) -> AsyncGenerator[TestClient, None]:
    """Instantiated test client with superadmin privileges"""
    _ = dockerdb
    async with TestClient(APP) as instance:
        # We need to be inside the app context to have db connection initialized
        await bind_and_create_all()
        user = await get_or_create_user("test-superadmin@example.com")
        token = jwt_env.issue(
            {
                "userid": uuid_to_b64(user.pk),  # type: ignore # false-positive
                "acl": [
                    {
                        "privilege": "fi.pvarki.superadmin",
                        "action": True,
                    }
                ],
            }
        )
        LOGGER.debug("superadmin-token={}".format(token))
        instance.headers.update({"Authorization": f"Bearer {token}"})

        LOGGER.debug("Yielding instance")
        yield instance
        LOGGER.debug("back")


@pytest_asyncio.fixture(scope="session")
async def unauth_client_sess(client: TestClient) -> AsyncGenerator[TestClient, None]:
    """Instantiated test client with no privileges, we use the (admin )client fixture to init the db"""
    _ = client
    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    async with TestClient(APP) as instance:
        LOGGER.debug("Yielding instance")
        yield instance
        LOGGER.debug("back")


@pytest_asyncio.fixture(scope="function")
async def unauth_client(unauth_client_sess: TestClient) -> AsyncGenerator[TestClient, None]:
    """Instantiated test client with no privileges, clear cookies between yields"""
    unauth_client_sess.cookie_jar.clear()
    yield unauth_client_sess
    unauth_client_sess.cookie_jar.clear()


@pytest_asyncio.fixture(scope="session")
async def enduser_object(client: TestClient) -> AsyncGenerator[User, None]:
    """Make sure end-user exist and yield it, we use the (admin )client fixture to init the db"""
    _ = client
    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    async with TestClient(APP) as _instance:
        user = await get_or_create_user("test-enduser@example.com")
        await user.update(sms="123457890").apply()
        user = await get_or_create_user("test-enduser@example.com")
        yield user


@pytest_asyncio.fixture(scope="session")
async def enduser_client(jwt_env: JWTHandler, client: TestClient) -> AsyncGenerator[TestClient, None]:
    """Instantiated test client with standard end-user privileges"""
    _ = client
    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    async with TestClient(APP) as instance:
        # We need to be inside the app context to have db connection initialized
        user = await get_or_create_user("test-enduser@example.com")
        token = jwt_env.issue(
            {
                "userid": uuid_to_b64(user.pk),  # type: ignore # false-positive
                "acl": models.User.default_acl.dict(),
            }
        )
        LOGGER.debug("enduser-token={}".format(token))
        instance.headers.update({"Authorization": f"Bearer {token}"})
        LOGGER.debug("Yielding instance")
        yield instance
        LOGGER.debug("back")


# FIXME: move the dockerdb and bind_and_create_all helpers to arkia11nmodels testhelpers
#       (and do a bit of refactoring with the old stuff there too)
async def bind_and_create_all() -> None:
    """Create all schemas and tables"""
    try:
        LOGGER.debug("Acquiring connection")
        async with WRAPPER.gino.acquire() as conn:
            LOGGER.debug("Acquiring transaction")
            async with conn.transaction():
                LOGGER.debug("Creating a11n schema")
                await models.db.status(sqlalchemy.schema.CreateSchema("a11n"))
                LOGGER.debug("Creating tables")
                await models.db.gino.create_all()
    except DuplicateSchemaError:
        pass


@pytest.fixture(scope="session")
def dockerdb(docker_ip: str, docker_services: Any, monkeysession: Any) -> Generator[str, None, None]:
    """start docker container for db"""
    LOGGER.debug("Monkeypatching env")
    _ = docker_services
    from arkia11nmodels import dbconfig  # pylint: disable=C0415

    mp_values = {
        "HOST": docker_ip,
        "PORT": docker_services.port_for("db", 5432),
        "PASSWORD": "apitestpwd",  # pragma: allowlist secret
        "USER": "postgres",
        "DATABASE": "a11napitest",
        "RETRY_LIMIT": "10",
        "RETRY_INTERVAL": "3",
    }
    LOGGER.debug("mp_values={}".format(mp_values))
    for key, value in mp_values.items():
        monkeysession.setenv(f"DB_{key}", str(value))
        monkeysession.setattr(dbconfig, key, value)

    new_dsn = sqlalchemy.engine.url.URL(
        drivername=dbconfig.DRIVER,
        username=dbconfig.USER,
        password=dbconfig.PASSWORD,
        host=dbconfig.HOST,
        port=dbconfig.PORT,
        database=dbconfig.DATABASE,
    )
    monkeysession.setattr(dbconfig, "DSN", new_dsn)

    # Wrapper got already initialized and does not inherit the new values
    monkeysession.setattr(WRAPPER, "dsn", new_dsn)
    monkeysession.setattr(WRAPPER, "retry_limit", int(mp_values["RETRY_LIMIT"]))
    monkeysession.setattr(WRAPPER, "retry_interval", int(mp_values["RETRY_INTERVAL"]))

    LOGGER.debug("yielding {}".format(str(dbconfig.DSN)))
    yield str(dbconfig.DSN)


@pytest_asyncio.fixture(scope="session")
async def three_roles(dockerdb: str) -> AsyncGenerator[List[Role], None]:
    """Create three roles and yield them, then nuke"""
    _ = dockerdb
    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    admins = Role(
        displayname="Test: SuperAdmins",
        acl=[
            {
                "privilege": "fi.pvarki.superadmin",
                "action": True,
            }
        ],
    )
    await admins.create()
    takadmins = Role(
        displayname="Test: TAK admins",
        acl=[
            {
                "privilege": "fi.pvarki.takserver:admin",
                "target": "someserver.arki.fi",
                "action": True,
            }
        ],
    )
    await takadmins.create()
    takusers = Role(
        displayname="Test: TAK users",
        acl=[
            {
                "privilege": "fi.pvarki.takserver:user",
                "target": "someserver.arki.fi:self",
                "action": True,
            }
        ],
    )
    await takusers.create()
    # Refresh the objects from DB and yield
    ret: List[Role] = []
    for role in (admins, takadmins, takusers):
        ret.append(await Role.get(role.pk))
    yield ret

    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    for role in ret:
        await UserRole.delete.where(UserRole.role == role.pk).gino.status()  # Nuke leftovers
        await role.delete()


@pytest_asyncio.fixture(scope="session")
async def three_users(dockerdb: str) -> AsyncGenerator[List[User], None]:
    """Create three roles and yield them, then nuke"""
    _ = dockerdb
    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    ret: List[User] = []
    domain = f"test{random.randint(1,100)}.example.com"  # nosec

    for idx in range(3):
        user = User(email=f"testuser{idx}@{domain}")  # nosec
        await user.create()
        ret.append(await User.get(user.pk))

    yield ret

    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    for user in ret:
        await UserRole.delete.where(UserRole.user == user.pk).gino.status()  # Nuke leftovers
        await user.delete()


@pytest.fixture
def overridden_token_url(monkeypatch: Any) -> Generator[str, None, None]:
    """set the override env and yield the url"""
    url_override = f"https://test{random.randint(1,100)}.override.example.com/"  # nosec
    monkeypatch.setenv("TOKEN_URL_OVERRIDE", url_override)
    monkeypatch.setattr(arkia11napi.config, "TOKEN_URL_OVERRIDE", url_override)
    monkeypatch.setattr(arkia11napi.views.tokens, "TOKEN_URL_OVERRIDE", url_override)

    yield url_override
