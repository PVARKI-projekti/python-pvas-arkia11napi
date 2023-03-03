"""Package level tests"""
from arkia11napi import __version__


def test_version() -> None:
    """Make sure version matches expected"""
    assert __version__ == "1.1.0"
