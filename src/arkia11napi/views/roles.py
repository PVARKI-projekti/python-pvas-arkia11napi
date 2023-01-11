"""Role related endpoints"""
from typing import List
import logging

import pendulum
from fastapi import APIRouter
from starlette import status
from arkia11nmodels.models import Role, User
from arkia11nmodels.schemas.role import DBRole, RoleCreate

from ..schemas.roles import RolePager
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


@ROLE_ROUTER.get("/api/v1/roles", tags=["roles"], response_model=RolePager)
async def list_roles() -> RolePager:
    """List roles"""
    # FIXME: check ACL
    roles = await Role.query.where(
        Role.deleted == None  # pylint: disable=C0121 ; # "is None" will create invalid query
    ).gino.all()
    if not roles:
        return RolePager(items=[], count=0)
    pdroles = [DBRole.parse_obj(role.to_dict()) for role in roles]
    return RolePager(
        count=len(pdroles),
        items=pdroles,
    )


@ROLE_ROUTER.get("/api/v1/roles/{pkstr}", tags=["roles"], response_model=DBRole)
async def get_role(pkstr: str) -> DBRole:
    """Get a single role"""
    # FIXME: check ACL
    role = await get_or_404(Role, pkstr)
    return DBRole.parse_obj(role.to_dict())


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
    role = await get_or_404(Role, pkstr)
    user = await get_or_404(User, userid)
    await role.remove_from(user)
