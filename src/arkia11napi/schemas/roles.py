"""Role schemas"""
import uuid

from arkia11nmodels.schemas.role import DBRole
from pydantic_collections import BaseCollectionModel
from libadvian.binpackers import ensure_str, uuid_to_b64

# pylint: disable=R0903


class RoleList(BaseCollectionModel[DBRole]):
    """List of Roles"""

    class Config:
        """Pydantic configs"""

        extra = "forbid"
        json_encoders = {uuid.UUID: lambda val: ensure_str(uuid_to_b64(val))}
