"""master cli group and other common stuff"""
from typing import Any, cast
import logging
import asyncio

import click
from arkia11nmodels.clickhelpers import bind_db
from arkia11nmodels import models
from arkia11napi.config import SUPERADMIN_ROLE_NAME


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


# FIXME: this should probably be in arkia11nmodels package
#   (but if moved there keep this command for backwards compatibility)
@cligroup.command()
@click.argument("admin_email")
def init_admin(admin_email: str) -> None:
    """Initialize admin role and add user with given email to it"""

    async def create_superadmins_role() -> models.Role:
        """Create (or get if it existed) the role for superadmins"""
        admins = await models.Role.query.where(models.Role.displayname == SUPERADMIN_ROLE_NAME).gino.first()
        refresh = False
        if admins is None:
            # Does not exist, create
            admins = models.Role(
                displayname=SUPERADMIN_ROLE_NAME,
                acl=[
                    {
                        "privilege": "fi.pvarki.superadmin",
                        "action": True,
                    }
                ],
            )
            await admins.create()
            refresh = True
        elif admins.deleted:
            # Was deleted, undelete
            await admins.update(deleted=None).apply()
            refresh = True

        if refresh:
            admins = await models.Role.get(admins.pk)

        return cast(models.Role, admins)

    async def action(admin_email: str) -> None:
        """Actual operation"""
        async with models.db.acquire() as conn:  # Cursors need transaction
            async with conn.transaction():
                admins = await create_superadmins_role()
                user = await models.User.query.where(models.User.email == admin_email).gino.first()
                refresh = False
                if user is None:
                    user = models.User(email=admin_email)
                    await user.create()
                    refresh = True
                elif user.deleted:
                    await user.update(deleted=None).apply()
                    refresh = True

                if refresh:
                    user = await models.User.get(user.pk)

                await admins.assign_to(user)

    asyncio.get_event_loop().run_until_complete(action(admin_email))
