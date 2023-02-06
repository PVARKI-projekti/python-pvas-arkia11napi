"""Role schemas"""
from typing import Sequence

from arkia11nmodels.schemas.role import DBRole
from pydantic import Field

from .pager import PagerBase

# pylint: disable=R0903


class RolePager(PagerBase):
    """List roles (paginated)"""

    items: Sequence[DBRole] = Field(default_factory=list, description="The roles on this page")
