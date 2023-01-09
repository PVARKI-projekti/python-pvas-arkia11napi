"""User schemas"""
from arkia11nmodels.schemas.user import DBUser
from pydantic_collections import BaseCollectionModel

# pylint: disable=R0903
class UserList(BaseCollectionModel[DBUser]):
    """List of Users"""
