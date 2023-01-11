"""User schemas"""
from typing import Sequence
import uuid

from arkia11nmodels.schemas.user import DBUser
from pydantic_collections import BaseCollectionModel
from libadvian.binpackers import ensure_str, uuid_to_b64
from pydantic import Field

from .pager import PagerBase

# pylint: disable=R0903


class UserPager(PagerBase):
    """List users (paginated)"""

    items: Sequence[DBUser] = Field(default_factory=list, description="The users on this page")


class UserList(BaseCollectionModel[DBUser]):
    """List of Users"""

    class Config:
        """Pydantic configs"""

        extra = "forbid"
        json_encoders = {uuid.UUID: lambda val: ensure_str(uuid_to_b64(val))}
