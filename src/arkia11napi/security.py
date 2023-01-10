"""Security related stuff"""
from __future__ import annotations
from typing import Optional, Any
import logging
from dataclasses import dataclass, field
import functools
from pathlib import Path

from libadvian.binpackers import ensure_utf8
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES, PUBLIC_KEY_TYPES
from cryptography.hazmat.backends import default_backend
from starlette.config import Config
from starlette.datastructures import Secret

LOGGER = logging.getLogger(__name__)
HDL_SINGLETON: Optional[JWTHandler] = None


cfg = Config(".env")

# mypy has issues with our partials to the config getter
@dataclass
class JWTHandler:
    """Helper/handler JWT creation related things"""

    privkeypath: Path = field(default_factory=functools.partial(cfg, "JWT_PRIVKEY_PATH", cast=Path))  # type: ignore
    pubkeypath: Path = field(default_factory=functools.partial(cfg, "JWT_PUBKEY_PATH", cast=Path))  # type: ignore
    keypasswd: Optional[Secret] = field(  # type: ignore
        default_factory=functools.partial(cfg, "JWT_PRIVKEY_PASS", cast=Secret, default=None)
    )
    algorithm: str = field(default_factory=functools.partial(cfg, "JWT_ALGORITHM", default="RS256"))  # type: ignore
    _privkey: PRIVATE_KEY_TYPES = field(init=False, repr=False)
    _pubkey: PUBLIC_KEY_TYPES = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Read the keys"""
        with self.privkeypath.open("rb") as fpntr:
            passphrase: Optional[bytes] = None
            if self.keypasswd:
                passphrase = ensure_utf8(str(self.keypasswd))
            self._privkey = serialization.load_pem_private_key(
                fpntr.read(), password=passphrase, backend=default_backend()
            )
        with self.pubkeypath.open("rb") as fpntr:
            self._pubkey = serialization.load_pem_public_key(fpntr.read(), backend=default_backend())

    @classmethod
    def singleton(cls, **kwargs: Any) -> JWTHandler:
        """Get a singleton"""
        global HDL_SINGLETON  # pylint: disable=W0602
        if HDL_SINGLETON is None:
            JWTHandler(**kwargs)
        assert HDL_SINGLETON is not None
        return HDL_SINGLETON
