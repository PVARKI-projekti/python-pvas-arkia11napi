"""Token endpoint schemas"""
from typing import Optional, Sequence
import uuid
import datetime

from arkia11nmodels.schemas.token import DBToken
from pydantic_collections import BaseCollectionModel
from pydantic import Field
from pydantic.main import BaseModel  # pylint: disable=E0611 # false positive
from libadvian.binpackers import ensure_str, uuid_to_b64

from .pager import PagerBase

# pylint: disable=R0903


class TokenPager(PagerBase):
    """List tokens (paginated)"""

    items: Sequence[DBToken] = Field(default_factory=list, description="The tokens on this page")


class TokenList(BaseCollectionModel[DBToken]):
    """List of tokens"""

    class Config:
        """Pydantic configs"""

        extra = "forbid"
        json_encoders = {uuid.UUID: lambda val: ensure_str(uuid_to_b64(val))}


class TokenRequestResponse(BaseModel, extra="forbid"):
    """Response to token request"""

    sent: bool = Field(
        description="Whether server sent the token or not."
        + " Note that unauthorized requests will always 'succeed' to prevent enumerating valid users"
    )
    errordetail: Optional[str] = Field(description="If there was an error this might tell more")


class TokenRefreshResponse(BaseModel, extra="forbid"):
    """Response to token refresh request"""

    jwt: str = Field(description="The newly issued JWT")


class TokenConsumeRequest(BaseModel, extra="forbid"):
    """Request to consume a token"""

    token: str = Field(description="The token UUID to consume")


class TokenConsumeResponse(BaseModel, extra="forbid"):
    """Response to token consume"""

    jwt: str = Field(description="The newly issued JWT")
    expires: datetime.datetime = Field(description="Token expiry")
    refresh_url: str = Field(description="URL for refreshing the token")
    redirect: Optional[str] = Field(default=None, nullable=True, description="The requested redirect url, if any")
