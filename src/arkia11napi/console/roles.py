"""Role related commands"""
from typing import Any
import asyncio
import logging
import json

import click
from arkia11nmodels.models import Role, User
from arkia11nmodels.models.role import UserRole

from .common import cligroup, get_and_print_json, list_and_print_json, create_and_print_json, get_by_uuid

# pylint: disable=R0913
LOGGER = logging.getLogger(__name__)


@cligroup.group()
@click.pass_context
def roles(ctx: Any) -> None:
    """role commands"""
    _ = ctx


@roles.command()
def ls() -> None:  # pylint: disable=C0103
    """List roles"""
    asyncio.get_event_loop().run_until_complete(list_and_print_json(Role))


@roles.command()
@click.argument("role_uuid")
def get(role_uuid: str) -> None:
    """Get role by uuid (pk)"""
    asyncio.get_event_loop().run_until_complete(get_and_print_json(Role, role_uuid))


@roles.command()
@click.argument("role_name")
@click.option(
    "--acl",
    type=str,
    default="[]",
    help="Set the ACL (JSON), DEFAULT: []",
)
@click.option(
    "--priority",
    type=int,
    default=1000,
    help="Set the merge priority, DEFAULT: 1000",
)
def create(role_name: str, acl: str, priority: int) -> None:
    """Create role"""
    # FIXME: create pydantic schema for ACL and verify the input
    init_kwars = {
        "displayname": role_name,
        "acl": json.loads(acl),
        "priority": priority,
    }
    asyncio.get_event_loop().run_until_complete(create_and_print_json(Role, init_kwars))


@roles.command()
@click.argument("role_uuid")
@click.argument("user_uuid")
def grant(role_uuid: str, user_uuid: str) -> None:
    """Grant the user the role"""

    async def action() -> None:
        """Do the async stuff"""
        role = await get_by_uuid(Role, role_uuid)
        user = await get_by_uuid(User, user_uuid)
        await role.assign_to(user)

    asyncio.get_event_loop().run_until_complete(action())


@roles.command()
@click.argument("role_uuid")
@click.argument("user_uuid")
def revoke(role_uuid: str, user_uuid: str) -> None:
    """Revoke the user from the role"""

    async def action() -> None:
        """Do the async stuff"""
        role = await get_by_uuid(Role, role_uuid)
        user = await get_by_uuid(User, user_uuid)
        await role.remove_from(user)

    asyncio.get_event_loop().run_until_complete(action())

@roles.command()
def lsgrant() -> None:
    """List role<->user links"""
    asyncio.get_event_loop().run_until_complete(list_and_print_json(UserRole))
