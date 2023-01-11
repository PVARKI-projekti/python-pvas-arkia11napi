"""Token relaed endpoints"""
import logging

import pendulum
from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse, FileResponse
from starlette import status
from arkia11nmodels.schemas.token import TokenRequest, DBToken
from arkia11nmodels.models import Token

from ..schemas.tokens import TokenRequestResponse, TokenPager
from ..helpers import get_or_404
from ..security import JWTHandler, JWTBearer, JWTPayload

LOGGER = logging.getLogger(__name__)
TOKEN_ROUTER = APIRouter()


@TOKEN_ROUTER.get("/api/v1/tokens/pubkey", tags=["tokens"], response_class=FileResponse)
async def public_key() -> FileResponse:
    """Return the public key for JWT verification (for automated setups in TLS environments)"""
    return FileResponse(path=JWTHandler.singleton().pubkeypath, media_type="text/pain", filename="jwt.pub")


@TOKEN_ROUTER.post("/api/v1/tokens", tags=["tokens"], response_model=TokenRequestResponse)
async def request_token(
    req: TokenRequest, jwt: JWTPayload = Depends(JWTBearer(auto_error=False))
) -> TokenRequestResponse:
    """Request a token"""
    # FIXME: implement (for optional auth check acl if they can see the result)
    _ = jwt
    _ = req
    return TokenRequestResponse(sent=True)


@TOKEN_ROUTER.get("/api/v1/tokens/use", tags=["tokens"], response_class=RedirectResponse)
@TOKEN_ROUTER.post("/api/v1/tokens/use", tags=["tokens"], response_class=RedirectResponse)
async def use_token(token: str) -> RedirectResponse:
    """Use a token"""
    # FIXME: implement
    _ = token
    # See-other needed to redirect from POST to GET
    return RedirectResponse("/api/v1", status_code=status.HTTP_303_SEE_OTHER)


@TOKEN_ROUTER.get("/api/v1/tokens", tags=["tokens"], response_model=TokenPager)
async def list_tokens(jwt: JWTPayload = Depends(JWTBearer(auto_error=True))) -> TokenPager:
    """List tokens"""
    # FIXME: use auth, check ACL
    _ = jwt
    tokens = await Token.query.where(
        Token.deleted == None  # pylint: disable=C0121 ; # "is None" will create invalid query
    ).gino.all()
    if not tokens:
        return TokenPager(items=[], count=0)
    pdtokens = [DBToken.parse_obj(token.to_dict()) for token in tokens]
    return TokenPager(
        count=len(pdtokens),
        items=pdtokens,
    )


# FIXME: Add patch method and pydanctic schema for uppdating
@TOKEN_ROUTER.get("/api/v1/tokens/{pkstr}", tags=["tokens"], response_model=DBToken)
async def get_token(pkstr: str, jwt: JWTPayload = Depends(JWTBearer(auto_error=False))) -> DBToken:
    """Get a single token"""
    # FIXME: use auth, check ACL
    _ = jwt
    token = await get_or_404(Token, pkstr)
    return DBToken.parse_obj(token.to_dict())


@TOKEN_ROUTER.delete("/api/v1/tokens/{pkstr}", tags=["tokens"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(pkstr: str, jwt: JWTPayload = Depends(JWTBearer(auto_error=False))) -> None:
    """Delete token"""
    # FIXME: use auth, check ACL
    _ = jwt
    token = await get_or_404(Token, pkstr)
    await token.update(deleted=pendulum.now("UTC")).apply()
