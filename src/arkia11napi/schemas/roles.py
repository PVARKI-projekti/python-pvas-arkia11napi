"""Role schemas"""
from typing import Sequence
import uuid

from arkia11nmodels.schemas.role import DBRole
from pydantic_collections import BaseCollectionModel
from libadvian.binpackers import ensure_str, uuid_to_b64
from pydantic import Field

from .pager import PagerBase

# pylint: disable=R0903


class RolePager(PagerBase):
    """List roles (paginated)"""

    items: Sequence[DBRole] = Field(default_factory=list, description="The roles on this page")


class RoleList(BaseCollectionModel[DBRole]):
    """List of Roles"""

    class Config:
        """Pydantic configs"""

        extra = "forbid"
        json_encoders = {uuid.UUID: lambda val: ensure_str(uuid_to_b64(val))}
