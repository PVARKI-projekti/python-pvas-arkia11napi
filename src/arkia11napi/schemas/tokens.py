"""Token endpoint schemas"""
from typing import Optional

from arkia11nmodels.schemas.token import DBToken
from pydantic_collections import BaseCollectionModel
from pydantic import Field
from pydantic.main import BaseModel  # pylint: disable=E0611 # false positive

# pylint: disable=R0903
class TokenList(BaseCollectionModel[DBToken]):
    """List of tokens"""


class TokenRequestResponse(BaseModel, extra="forbid"):
    """Response to token request"""

    sent: bool = Field(
        description="Whether server sent the token or not."
        + " Note that unauthorized requests will always 'succeed' to prevent enumerating valid users"
    )
    errordetail: Optional[str] = Field(description="If there was an error this might tell more")
