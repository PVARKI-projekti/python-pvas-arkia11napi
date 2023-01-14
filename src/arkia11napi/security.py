"""Security related stuff"""
# importing annotations from future bloews up fastapi dependency injection
from typing import Optional, Any, Dict, Mapping, List, MutableMapping
import logging
from dataclasses import dataclass, field
import functools
from pathlib import Path
import uuid

import jwt as pyJWT  # too easy to accidentally override the module
import pendulum
from libadvian.binpackers import ensure_utf8, b64_to_uuid, ensure_str
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES, PUBLIC_KEY_TYPES
from cryptography.hazmat.backends import default_backend
from starlette.config import Config
from starlette.datastructures import Secret
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from arkia11nmodels.schemas.role import ACLItem
from arkia11nmodels.models import User

LOGGER = logging.getLogger(__name__)
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

    # Non-init public props
    pubkey: PUBLIC_KEY_TYPES = field(init=False)

    # Private props
    _privkey: PRIVATE_KEY_TYPES = field(init=False, repr=False)

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
            self.pubkey = serialization.load_pem_public_key(fpntr.read(), backend=default_backend())

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
        return pyJWT.decode(jwt=token, key=self.pubkey, algorithms=[self.config.algorithm])  # type: ignore

    @classmethod
    def singleton(cls, **kwargs: Any) -> "JWTHandler":
        """Get a singleton"""
        global HDL_SINGLETON  # pylint: disable=W0603
        if HDL_SINGLETON is None:
            HDL_SINGLETON = JWTHandler(**kwargs)
        assert HDL_SINGLETON is not None
        return HDL_SINGLETON


HDL_SINGLETON: Optional[JWTHandler] = None

JWTPayload = Mapping[str, Any]


class JWTBearer(HTTPBearer):  # pylint: disable=R0903
    """Check JWT bearer tokens"""

    async def __call__(self, request: Request) -> Optional[JWTPayload]:  # type: ignore[override]
        credentials: Optional[HTTPAuthorizationCredentials] = await super().__call__(request)
        if not credentials:
            # autp-error will have raised already if no auth header
            return None
        if credentials.scheme != "Bearer":
            raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
        payload: Optional[Mapping[str, Any]] = None
        try:
            payload = JWTHandler.singleton().decode(credentials.credentials)
        except Exception as exc:  # pylint: disable=W0703
            LOGGER.exception("Got problem {} decoding {}".format(exc, credentials))
        if not payload and self.auto_error:
            raise HTTPException(status_code=403, detail="Invalid or expired token.")
        # Inject into request state to avoid Repeating Myself
        request.state.jwt = payload
        return payload


def jwt_acl_by_privilege(jwt: JWTPayload) -> MutableMapping[str, List[ACLItem]]:
    """Helper to map the ACL by privilege name"""
    ret: Dict[str, List[ACLItem]] = {}
    if "acl" not in jwt or not jwt["acl"]:
        LOGGER.warning("No 'acl' key in JWT, this should not be")
        return ret
    for aclitem in [ACLItem.parse_obj(item) for item in jwt["acl"]]:
        if aclitem.privilege not in ret:
            ret[aclitem.privilege] = []
        ret[aclitem.privilege].append(aclitem)
    return ret


# FIXME: this should be in libadvian
def graceful_decode_uuid(datain: str) -> Optional[uuid.UUID]:
    """Try to decode input as uuid"""
    try:
        parsed = uuid.UUID(ensure_str(datain))
        return parsed
    except ValueError:
        try:
            parsed = b64_to_uuid(datain)
            return parsed
        except ValueError:
            pass
    return None


# FIXME: This should be in some common library of ours
def check_acl(  # pylint: disable=R0912
    jwt: JWTPayload,
    require_privilege: str,
    self_user: Optional[User] = None,
    require_target: Optional[str] = None,
    auto_error: bool = True,
) -> bool:
    """Check ACL, returns granted or not (and in case of auto-error will throw 403,
    self user is the user that would match a 'self' targeted rule"""
    # PONDER: doing just a fixed (or startswith) comparison with target might not be enough, do we allow callables ?
    #        or should those use cases just handle it themselves
    by_privilege = jwt_acl_by_privilege(jwt)
    LOGGER.debug(
        "require_privilege={}, by_privilege={}, self_user={},require_target={}".format(
            by_privilege, require_privilege, self_user, require_target
        )
    )
    if "fi.arki.superadmin" in by_privilege:
        for item in by_privilege["fi.arki.superadmin"]:
            if item.action is True:  # we do a hard type check on purpose
                return True  # SuperAdmins are always good for everything

    # PONDER: do we need "startswith" style comparisons ??
    if require_privilege not in by_privilege:
        if not auto_error:
            return False
        raise HTTPException(status_code=403, detail="Required privilege not granted.")

    for item in by_privilege[require_privilege]:
        # Ignore actions that are not explicit grants
        if item.action is not True:
            continue
        # If target is required ignore those that do not match
        if require_target and item.target != require_target:
            continue
        # No target defined or required, we're good
        if not item.target:
            return True

        # Match self-target
        if item.target == "self":
            if not self_user:
                LOGGER.warning("{} targets self but self_user not defined".format(item))
                continue
            if "userid" not in jwt:
                LOGGER.warning("{} targets self but jwt has no key 'userid'".format(item))
                continue
            jwt_user_uuid = graceful_decode_uuid(jwt["userid"])
            if jwt_user_uuid == self_user.pk:
                return True

    # fell through, deny-by-default
    if not auto_error:
        return False
    raise HTTPException(status_code=403, detail="Required privilege not granted.")
