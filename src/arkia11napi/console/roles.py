"""Role related commands"""
import asyncio
from typing import Any, List, Dict
import logging
import json

import click
from arkia11nmodels.models import db, Role

from .common import cligroup

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

    async def get_and_print_json() -> None:
        """Wrap the async stuff"""
        dbroles = await db.all(Role.query)
        ret: List[Dict[str, Any]] = []
        for role in dbroles:
            ret.append(role.to_dict())
        click.echo(json.dumps(ret))

    asyncio.get_event_loop().run_until_complete(get_and_print_json())
