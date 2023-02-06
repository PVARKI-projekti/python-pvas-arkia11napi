"""Test security helpers"""
import logging

import pendulum

from arkia11napi.security import JWTHandler, JWT_LIFETIME

LOGGER = logging.getLogger(__name__)


def test_jwt_singleton() -> None:
    """Make sure we can fetch the singleton"""
    hdl = JWTHandler.singleton()
    assert hdl._privkey  # pylint: disable=W0212
    assert hdl.pubkey  # pylint: disable=W0212


def test_jwt_roundtrip() -> None:
    """Encode some claims and decode them"""
    hdl = JWTHandler.singleton()
    claims = {"cn": "kimmo", "something": 123.4, "nested": {"subkey": "value"}, "list": [{"subkey": "value"}]}
    token = hdl.issue(claims)
    decoded = hdl.decode(token)
    LOGGER.debug("decoded={}".format(repr(decoded)))

    # Check times
    issued = pendulum.from_timestamp(decoded["iat"], tz="UTC")
    expires = pendulum.from_timestamp(decoded["exp"], tz="UTC")
    LOGGER.debug("issued={}, expires={}".format(issued, expires))
    assert (pendulum.now("UTC") - issued).in_seconds() < 1.0
    assert (expires - pendulum.now("UTC")).in_seconds() > (JWT_LIFETIME - 2.0)

    # check claims match
    assert decoded["cn"] == claims["cn"]
    assert decoded["something"] == claims["something"]
    assert decoded["nested"]["subkey"] == claims["nested"]["subkey"]  # type: ignore
    assert decoded["list"][0]["subkey"] == claims["list"][0]["subkey"]  # type: ignore
