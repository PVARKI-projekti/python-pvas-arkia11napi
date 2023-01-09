"""Role related endpoints"""
from typing import List
import logging

import pendulum
from fastapi import APIRouter
from starlette import status
from arkia11nmodels.models import Role, User
from arkia11nmodels.schemas.role import DBRole, RoleCreate

from ..schemas.roles import RoleList
from ..schemas.users import UserList
from ..helpers import get_or_404


LOGGER = logging.getLogger(__name__)
# FIXME insert auth dependency, all our points need auth
ROLE_ROUTER = APIRouter()


@ROLE_ROUTER.post("/api/v1/roles", tags=["roles"], response_model=DBRole)
async def create_role(role: RoleCreate) -> DBRole:
    """List roles"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    _ = role
    raise NotImplementedError()


@ROLE_ROUTER.get("/api/v1/roles", tags=["roles"], response_model=RoleList)
async def list_roles() -> RoleList:
    """List roles"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    return RoleList([])


@ROLE_ROUTER.get("/api/v1/roles/{pkstr}", tags=["roles"], response_model=DBRole)
async def get_role(pkstr: str) -> DBRole:
    """Get a single role"""
    # FIXME: check ACL
    return await get_or_404(Role, pkstr)


@ROLE_ROUTER.delete("/api/v1/roles/{pkstr}", tags=["roles"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(pkstr: str) -> None:
    """Delete role"""
    # FIXME: check ACL
    role = await get_or_404(Role, pkstr)
    await role.update(deleted=pendulum.now("UTC"))


@ROLE_ROUTER.get("/api/v1/roles/{pkstr}/users", tags=["roles"], response_model=UserList)
async def get_role_assignees(pkstr: str) -> UserList:
    """Get list of users assigned to role"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    _role = await get_or_404(Role, pkstr)
    return UserList([])


@ROLE_ROUTER.post("/api/v1/roles/{pkstr}/users", tags=["roles"], response_model=UserList)
async def assign_role(pkstr: str, userids: List[str]) -> UserList:
    """Assign users this role, returns list of users added"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    _role = await get_or_404(Role, pkstr)
    _ = userids
    return UserList([])


@ROLE_ROUTER.delete("/api/v1/roles/{pkstr}/users/{userid}", tags=["roles"], status_code=status.HTTP_204_NO_CONTENT)
async def remove_role(pkstr: str, userid: str) -> None:
    """Remove user from this role"""
    # FIXME: user a pager class, check ACL
    # FIXME: implement
    role = await get_or_404(Role, pkstr)
    user = await get_or_404(User, userid)
    await role.remove_from(user)
