"""User related endpoints"""
from typing import List
import logging

import pendulum
from fastapi import APIRouter
from starlette import status
from arkia11nmodels.models import User, Role
from arkia11nmodels.schemas.user import DBUser, UserCreate

from ..schemas.roles import RoleList
from ..schemas.users import UserList
from ..helpers import get_or_404


LOGGER = logging.getLogger(__name__)
# FIXME insert auth dependency, all our points need auth
USER_ROUTER = APIRouter()


@USER_ROUTER.post("/api/v1/users", tags=["users"], response_model=DBUser)
async def create_user(role: UserCreate) -> DBUser:
    """Create user"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    _ = role
    raise NotImplementedError()


@USER_ROUTER.get("/api/v1/users", tags=["users"], response_model=UserList)
async def list_users() -> UserList:
    """List users"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    return UserList([])


@USER_ROUTER.get("/api/v1/users/{pkstr}", tags=["users"], response_model=DBUser)
async def get_user(pkstr: str) -> DBUser:
    """Get a single user"""
    # FIXME: check ACL
    return await get_or_404(User, pkstr)


@USER_ROUTER.delete("/api/v1/users/{pkstr}", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(pkstr: str) -> None:
    """Delete user"""
    # FIXME: check ACL
    user = await get_or_404(User, pkstr)
    await user.update(deleted=pendulum.now("UTC"))


@USER_ROUTER.get("/api/v1/users/{pkstr}/roles", tags=["users"], response_model=RoleList)
async def get_roles(pkstr: str) -> RoleList:
    """Get list of roles assigned to user"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    _user = await get_or_404(User, pkstr)
    return RoleList([])


@USER_ROUTER.post("/api/v1/users/{pkstr}/roles", tags=["users"], response_model=RoleList)
async def assign_roles(pkstr: str, roleids: List[str]) -> RoleList:
    """Assign roles this user, returns list of roles added"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    _user = await get_or_404(User, pkstr)
    _ = roleids
    return RoleList([])


@USER_ROUTER.delete("/api/v1/users/{pkstr}/roles/{roleid}", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
async def remove_role(pkstr: str, roleid: str) -> None:
    """Remove user from this role, returns list of users removed"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    user = await get_or_404(User, pkstr)
    role = await get_or_404(Role, roleid)
    await role.remove_from(user)
