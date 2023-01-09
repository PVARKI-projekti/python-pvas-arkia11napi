"""User related commands"""
from typing import Any
import asyncio
import logging

import click
from arkia11nmodels.models import User
from arkia11nmodels.clickhelpers import get_and_print_json, list_and_print_json, create_and_print_json

from .common import cligroup

# pylint: disable=R0913
LOGGER = logging.getLogger(__name__)


@cligroup.group()
@click.pass_context
def users(ctx: Any) -> None:
    """user commands"""
    _ = ctx


@users.command()
def ls() -> None:  # pylint: disable=C0103
    """List users"""
    asyncio.get_event_loop().run_until_complete(list_and_print_json(User))


@users.command()
@click.argument("user_uuid")
def get(user_uuid: str) -> None:
    """Get user by uuid (pk)"""
    asyncio.get_event_loop().run_until_complete(get_and_print_json(User, user_uuid))


@users.command()
@click.argument("user_email")
def create(user_email: str) -> None:
    """Create user"""
    init_kwars = {
        "email": user_email,
    }
    asyncio.get_event_loop().run_until_complete(create_and_print_json(User, init_kwars))
