"""User schemas"""
from typing import Sequence

from arkia11nmodels.schemas.user import DBUser
from pydantic import Field

from .pager import PagerBase

# pylint: disable=R0903


class UserPager(PagerBase):
    """List users (paginated)"""

    items: Sequence[DBUser] = Field(default_factory=list, description="The users on this page")
