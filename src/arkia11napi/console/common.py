"""master cli group and other common stuff"""
from typing import Any
import logging
import asyncio

import click
from arkia11nmodels.clickhelpers import bind_db


from arkia11napi import __version__

# pylint: disable=R0913
LOGGER = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__)
@click.option("-l", "--loglevel", help="Python log level, 10=DEBUG, 20=INFO, 30=WARNING, 40=CRITICAL", default=30)
@click.option("-v", "--verbose", count=True, help="Shorthand for info/debug loglevel (-v/-vv)")
@click.pass_context
def cligroup(ctx: Any, loglevel: int, verbose: int) -> None:
    """CLI tools for initializing admins etc directly to database"""
    if verbose == 1:
        loglevel = 20
    if verbose >= 2:
        loglevel = 10
    logging.getLogger("").setLevel(loglevel)
    LOGGER.setLevel(loglevel)
    ctx.ensure_object(dict)
    asyncio.get_event_loop().run_until_complete(bind_db())
