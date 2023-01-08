"""CLI entrypoints for arkia11napi"""
import logging

from libadvian.logging import init_logging

from .common import cligroup
from .roles import roles
from .users import users

LOGGER = logging.getLogger(__name__)


cligroup.add_command(roles)
cligroup.add_command(users)


def arkia11napi_cli() -> None:
    """CLI tools for initializing admins etc directly to database"""
    init_logging(logging.WARNING)
    LOGGER.setLevel(logging.WARNING)
    cligroup()  # pylint: disable=E1120
