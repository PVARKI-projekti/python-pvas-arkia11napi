"""Token relaed endpoints"""
import logging

from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from starlette import status
from arkia11nmodels.schemas.token import TokenRequest, DBToken
from arkia11nmodels.models import Token

from ..schemas.tokens import TokenList, TokenRequestResponse
from ..helpers import get_or_404


LOGGER = logging.getLogger(__name__)
TOKEN_ROUTER = APIRouter()


@TOKEN_ROUTER.post("/api/v1/tokens", tags=["tokens"], response_model=TokenRequestResponse)
async def request_token(req: TokenRequest) -> TokenRequestResponse:
    """Request a token"""
    # FIXME: implement (for optional auth check acl if they can see the result)
    _ = req
    return TokenRequestResponse(sent=True)


@TOKEN_ROUTER.post("/api/v1/tokens/use", tags=["tokens"], response_class=RedirectResponse)
async def use_token(token: str) -> RedirectResponse:
    """Use a token"""
    # FIXME: implement
    _ = token
    # See-other needed to redirect from POST to GET
    return RedirectResponse("/api/v1", status_code=status.HTTP_303_SEE_OTHER)


@TOKEN_ROUTER.get("/api/v1/tokens", tags=["tokens"], response_model=TokenList)
async def list_tokens() -> TokenList:
    """List tokens"""
    # FIXME: user a pager class, use auth, check ACL
    # FIXME: implement
    return TokenList([])


@TOKEN_ROUTER.get("/api/v1/tokens/{pkstr}", tags=["tokens"], response_model=DBToken)
async def get_token(pkstr: str) -> DBToken:
    """Get a single token"""
    # FIXME: use auth, check ACL
    return await get_or_404(Token, pkstr)


@TOKEN_ROUTER.delete("/api/v1/tokens/{pkstr}", tags=["tokens"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(pkstr: str) -> None:
    """Delete token"""
    # FIXME: use auth, check ACL
    token = await get_or_404(Token, pkstr)
    await token.delete()
