"""Token relaed endpoints"""
from typing import List, cast
import logging

import pendulum
from libadvian.binpackers import uuid_to_b64
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, FileResponse
from fastapi_mail import MessageSchema, MessageType
from starlette import status
from starlette.exceptions import HTTPException
from starlette.datastructures import URL
from arkia11nmodels.schemas.token import TokenRequest, DBToken
from arkia11nmodels.models import Token, User

from ..schemas.tokens import TokenRequestResponse, TokenPager
from ..helpers import get_or_404
from ..security import JWTHandler, JWTBearer, JWTPayload, check_acl
from ..config import JWT_COOKIE_NAME, JWT_COOKIE_DOMAIN, JWT_COOKIE_SECURE
from ..mailer import singleton as getmailer

LOGGER = logging.getLogger(__name__)
TOKEN_ROUTER = APIRouter()


@TOKEN_ROUTER.get("/api/v1/tokens/pubkey", tags=["tokens"], response_class=FileResponse)
async def public_key() -> FileResponse:
    """Return the public key for JWT verification (for automated setups in TLS environments)"""
    return FileResponse(path=JWTHandler.singleton().pubkeypath, media_type="text/pain", filename="jwt.pub")


@TOKEN_ROUTER.post(
    "/api/v1/tokens", tags=["tokens"], response_model=TokenRequestResponse, status_code=status.HTTP_201_CREATED
)
async def request_token(
    tkreq: TokenRequest, request: Request, jwt: JWTPayload = Depends(JWTBearer(auto_error=False))
) -> TokenRequestResponse:
    """Request a token"""
    if tkreq.deliver_via != "email":
        return TokenRequestResponse(sent=False, errordetail="Only email delivery supported ATM")

    user = await User.query.where(getattr(User, tkreq.deliver_via) == tkreq.target).gino.first()
    if not user:
        LOGGER.info("Could not find matching user for {}".format(tkreq))
        if not check_acl(jwt, "fi.pvarki.arkia11nmodels.token:read", auto_error=False):
            return TokenRequestResponse(sent=False, errordetail="User not found")
        return TokenRequestResponse(sent=True)

    user = cast(User, user)
    token = Token.for_user(user)
    send_to = getattr(user, tkreq.deliver_via)
    token.sent_to = send_to
    if not tkreq.redirect is None:
        redir_verify = URL(tkreq.redirect)  # Make sure the url is parseable
        token.redirect = str(redir_verify)
    # FIXME: figure what to do with audit_meta
    await token.create()
    token = Token.get(token.pk)
    token_url = request.url_for("use_token", token=uuid_to_b64(token.pk))  # type: ignore # false positive

    mailer = getmailer()
    msg = MessageSchema(
        subject="PVARKI login token",  # FIXME: make configurable in the request or env based default
        recipients=[send_to],
        subtype=MessageType.plain,
        template_body={"login_url": token_url},
    )
    try:
        await mailer.send_message(msg, template_name="token_email.txt")
    except Exception as exc:  # pylint: disable=W0703
        LOGGER.exception("mail delivery failure {}".format(exc))
        await token.delete()  # completely remove tokens whose delivery failed
        return TokenRequestResponse(sent=False, errordetail="Email send failed")

    return TokenRequestResponse(sent=True)


@TOKEN_ROUTER.get("/api/v1/tokens/use", tags=["tokens"], response_class=RedirectResponse, name="use_token")
@TOKEN_ROUTER.post("/api/v1/tokens/use", tags=["tokens"], response_class=RedirectResponse)
async def use_token(token: str, request: Request) -> RedirectResponse:
    """Use a token"""
    token_db = await get_or_404(Token, token)
    token_db = cast(Token, token_db)
    if token_db.used:
        raise HTTPException(
            status.HTTP_410_GONE,
            "{} already used on {}".format(token, token_db.used.isoformat()),
        )
    if token_db.expires < pendulum.now("UTC"):
        raise HTTPException(
            status.HTTP_410_GONE,
            "{} expired on {}".format(token, token_db.expires.isoformat()),
        )
    user = await User.get(token_db.user)
    if not user or user.deleted:
        raise HTTPException(
            status.HTTP_410_GONE,
            "User {} is no longer valid".format(token_db.user),
        )

    jwt = JWTHandler.singleton().issue(
        {
            "userid": uuid_to_b64(user.pk),
            "acl": User.default_acl.dict(),  # FIXME: merge role ACLs
        }
    )
    new_meta = dict(token_db.audit_meta)
    # FIXME: figure what to do with audit_meta
    await token_db.update(audit_meta=new_meta, used=pendulum.now("UTC"))

    if token_db.redirect is None:
        destination = request.url_for("my_user")
    else:
        destination = URL(token_db.redirect)
        destination.include_query_params(JWT_COOKIE_NAME=jwt)

    # See-other needed to redirect from POST to GET
    resp = RedirectResponse(str(destination), status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=JWT_COOKIE_NAME,
        value=jwt,
        httponly=True,  # The url we redirect to must pass the token back to any JS that needs to use it
        domain=JWT_COOKIE_DOMAIN,
        secure=JWT_COOKIE_SECURE,
    )
    return resp


@TOKEN_ROUTER.get("/api/v1/tokens", tags=["tokens"], response_model=TokenPager)
async def list_tokens(jwt: JWTPayload = Depends(JWTBearer(auto_error=True))) -> TokenPager:
    """List tokens, audit_meta is always empty in this list, get a specific token with audit privilege to see it"""
    check_acl(jwt, "fi.pvarki.arkia11nmodels.token:read")
    tokens = (
        await Token.query.where(Token.deleted == None)  # pylint: disable=C0121 ; # "is None" will create invalid query
        .order_by(Token.created.desc())
        .gino.all()
    )
    if not tokens:
        return TokenPager(items=[], count=0)
    pdtokens: List[DBToken] = []
    for token in tokens:
        pdtoken = DBToken.parse_obj(token.to_dict())
        pdtoken.audit_meta = {}
        pdtokens.append(pdtoken)
    return TokenPager(
        count=len(pdtokens),
        items=pdtokens,
    )


# FIXME: Add patch method and pydanctic schema for uppdating
@TOKEN_ROUTER.get("/api/v1/tokens/{pkstr}", tags=["tokens"], response_model=DBToken)
async def get_token(pkstr: str, jwt: JWTPayload = Depends(JWTBearer(auto_error=False))) -> DBToken:
    """Get a single token, audit_meta is only visible to those with audit privilege"""
    token = await get_or_404(Token, pkstr)
    user = await User.Get(token.user)
    check_acl(jwt, "fi.pvarki.arkia11nmodels.token:read", self_user=user)
    if not check_acl(jwt, "fi.pvarki.arkia11nmodels.token:audit", self_user=user, auto_error=False):
        token.audit_meta = {}
    return DBToken.parse_obj(token.to_dict())


@TOKEN_ROUTER.delete("/api/v1/tokens/{pkstr}", tags=["tokens"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(pkstr: str, jwt: JWTPayload = Depends(JWTBearer(auto_error=False))) -> None:
    """Delete token"""
    token = await get_or_404(Token, pkstr)
    user = await User.Get(token.user)
    check_acl(jwt, "fi.pvarki.arkia11nmodels.token:delete", self_user=user)
    await token.update(deleted=pendulum.now("UTC")).apply()
