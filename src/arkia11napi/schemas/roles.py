"""Role schemas"""
from arkia11nmodels.schemas.role import DBRole
from pydantic_collections import BaseCollectionModel

# pylint: disable=R0903


class RoleList(BaseCollectionModel[DBRole]):
    """List of Roles"""
