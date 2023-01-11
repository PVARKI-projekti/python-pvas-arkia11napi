"""User related endpoints"""
from typing import List
import logging

import pendulum
from fastapi import APIRouter, Depends
from starlette import status
from arkia11nmodels.models import User, Role
from arkia11nmodels.schemas.user import DBUser, UserCreate
from arkia11nmodels.schemas.role import DBRole, RoleList

from ..schemas.users import UserPager
from ..helpers import get_or_404
from ..security import JWTBearer


LOGGER = logging.getLogger(__name__)
USER_ROUTER = APIRouter(dependencies=[Depends(JWTBearer(auto_error=True))])


@USER_ROUTER.post("/api/v1/users", tags=["users"], response_model=DBUser)
async def create_user(pduser: UserCreate) -> DBUser:
    """Create user"""
    # FIXME: check ACL
    user = User(**pduser.dict())
    await user.create()
    refresh = await User.get(user.pk)
    return DBUser.parse_obj(refresh.to_dict())


@USER_ROUTER.get("/api/v1/users", tags=["users"], response_model=UserPager)
async def list_users() -> UserPager:
    """List users"""
    # FIXME: check ACL
    users = await User.query.where(
        User.deleted == None  # pylint: disable=C0121 ; # "is None" will create invalid query
    ).gino.all()
    if not users:
        return UserPager(items=[], count=0)
    pdusers = [DBUser.parse_obj(user.to_dict()) for user in users]
    return UserPager(
        count=len(pdusers),
        items=pdusers,
    )


# FIXME: Add patch method and pydanctic schema for uppdating
@USER_ROUTER.get("/api/v1/users/{pkstr}", tags=["users"], response_model=DBUser)
async def get_user(pkstr: str) -> DBUser:
    """Get a single user"""
    # FIXME: check ACL
    user = await get_or_404(User, pkstr)
    return DBUser.parse_obj(user.to_dict())


@USER_ROUTER.delete("/api/v1/users/{pkstr}", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(pkstr: str) -> None:
    """Delete user"""
    # FIXME: check ACL
    user = await get_or_404(User, pkstr)
    await user.update(deleted=pendulum.now("UTC")).apply()


@USER_ROUTER.get("/api/v1/users/{pkstr}/roles", tags=["users"], response_model=RoleList)
async def get_roles(pkstr: str) -> RoleList:
    """Get list of roles assigned to user"""
    # FIXME: user a pager class, check ACL
    user = await get_or_404(User, pkstr)
    roles = await Role.resolve_user_roles(user)
    pdroles = [DBRole.parse_obj(role.to_dict()) for role in roles]
    return RoleList(pdroles)


@USER_ROUTER.post("/api/v1/users/{pkstr}/roles", tags=["users"], response_model=RoleList)
async def assign_roles(pkstr: str, roleids: List[str]) -> RoleList:
    """Assign roles this user, returns list of roles added (if role is not in list user already had that role)"""
    # FIXME: check ACL
    user = await get_or_404(User, pkstr)
    # This will sadly mess things up for asyncpg with the way the gino middleware is set up
    # roles = await asyncio.gather(*[get_or_404(Role, roleid) for roleid in roleids])
    lst = []
    for roleid in roleids:
        role = await get_or_404(Role, roleid)
        if await role.assign_to(user):
            lst.append(DBRole.parse_obj(role.to_dict()))
    return RoleList(lst)


@USER_ROUTER.delete("/api/v1/users/{pkstr}/roles/{roleid}", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
async def remove_role(pkstr: str, roleid: str) -> None:
    """Remove user from this role, returns list of users removed"""
    # FIXME: check ACL
    user = await get_or_404(User, pkstr)
    role = await get_or_404(Role, roleid)
    await role.remove_from(user)
