"""Test security helpers"""

from arkia11napi.security import JWTHandler


def test_jwt_singleton() -> None:
    """Make sure we can fetch the singleton"""
    hdl = JWTHandler.singleton()
    assert hdl._privkey  # pylint: disable=W0212
    assert hdl._pubkey  # pylint: disable=W0212
