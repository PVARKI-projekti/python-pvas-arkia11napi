"""User schemas"""
import uuid

from arkia11nmodels.schemas.user import DBUser
from pydantic_collections import BaseCollectionModel
from libadvian.binpackers import ensure_str, uuid_to_b64

# pylint: disable=R0903
class UserList(BaseCollectionModel[DBUser]):
    """List of Users"""

    class Config:
        """Pydantic configs"""

        extra = "forbid"
        json_encoders = {uuid.UUID: lambda val: ensure_str(uuid_to_b64(val))}
