"""Security related stuff"""
from __future__ import annotations
from typing import Optional, Any, Dict
import logging
from dataclasses import dataclass, field
import functools
from pathlib import Path

import jwt as pyJWT  # too easy to accidentally override the module
import pendulum
from libadvian.binpackers import ensure_utf8
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES, PUBLIC_KEY_TYPES
from cryptography.hazmat.backends import default_backend
from starlette.config import Config
from starlette.datastructures import Secret

LOGGER = logging.getLogger(__name__)
HDL_SINGLETON: Optional[JWTHandler] = None
JWT_LIFETIME = 60 * 60 * 2  # 2 hours in seconds

cfg = Config(".env")


# mypy has issues with our partials to the config getter
@dataclass
class JWTHandlerConfig:
    """Config options for jwt encode/decode"""

    algorithm: str = field(default_factory=functools.partial(cfg, "JWT_ALGORITHM", default="RS256"))  # type: ignore
    lifetime: int = field(  # type: ignore
        default_factory=functools.partial(cfg, "JWT_LIFETIME", cast=int, default=JWT_LIFETIME)
    )
    issuer: Optional[str] = field(default_factory=functools.partial(cfg, "JWT_ISSUER", default=None))
    audience: Optional[str] = field(default_factory=functools.partial(cfg, "JWT_AUDIENCE", default=None))


@dataclass
class JWTHandler:
    """Helper/handler JWT creation related things"""

    privkeypath: Path = field(default_factory=functools.partial(cfg, "JWT_PRIVKEY_PATH", cast=Path))  # type: ignore
    pubkeypath: Path = field(default_factory=functools.partial(cfg, "JWT_PUBKEY_PATH", cast=Path))  # type: ignore
    keypasswd: Optional[Secret] = field(  # type: ignore
        default_factory=functools.partial(cfg, "JWT_PRIVKEY_PASS", cast=Secret, default=None)
    )
    config: JWTHandlerConfig = field(default_factory=JWTHandlerConfig)

    # Private props
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

    def issue(self, claims: Dict[str, Any]) -> str:
        """Issue JWT with claims, sets some basic defaults"""
        now = pendulum.now("UTC")
        claims["nbf"] = now
        claims["iat"] = now
        claims["exp"] = now + pendulum.duration(seconds=self.config.lifetime)
        if self.config.issuer:
            claims["iss"] = self.config.issuer
        if self.config.audience:
            claims["aud"] = self.config.audience
        return pyJWT.encode(payload=claims, key=self._privkey, algorithm=self.config.algorithm)  # type: ignore

    def decode(self, token: str) -> Dict[str, Any]:
        """Decode the token"""
        return pyJWT.decode(jwt=token, key=self._pubkey, algorithms=[self.config.algorithm])  # type: ignore

    @classmethod
    def singleton(cls, **kwargs: Any) -> JWTHandler:
        """Get a singleton"""
        global HDL_SINGLETON  # pylint: disable=W0602
        if HDL_SINGLETON is None:
            JWTHandler(**kwargs)
        assert HDL_SINGLETON is not None
        return HDL_SINGLETON
