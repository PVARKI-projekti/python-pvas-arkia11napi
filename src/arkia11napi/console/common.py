"""master cli group and other common stuff"""
from typing import Any, List, Dict, Union, Type
import logging
import asyncio
import uuid
import json
import datetime

import click
from libadvian.binpackers import b64_to_uuid, ensure_utf8, ensure_str, uuid_to_b64
from arkia11nmodels import dbconfig, models
from arkia11nmodels.models.base import BaseModel

from arkia11napi import __version__

# pylint: disable=R0913
LOGGER = logging.getLogger(__name__)

# FIXME: move to libadvian.hashinghelpers
class DateTimeEncoder(json.JSONEncoder):
    """Handle datetimes in JSON"""

    def default(self, o: Any) -> Any:
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat().replace("+00:00", "Z")
        return super().default(o)


class UUIDEncoder(json.JSONEncoder):
    """Handle UUIDs in JSON (encode as base64)"""

    def default(self, o: Any) -> Any:
        if isinstance(o, uuid.UUID):
            return ensure_str(uuid_to_b64(o))
        return super().default(o)


class DBTypesEncoder(DateTimeEncoder, UUIDEncoder):
    """All the encoders we need"""


async def bind_db() -> None:
    """Bind the db"""
    await models.db.set_bind(dbconfig.DSN)


async def get_and_print_json(klass: Type[BaseModel], pkin: Union[bytes, str]) -> None:
    """helper to get and dump as JSON object of type klass"""
    try:
        getpk = b64_to_uuid(ensure_utf8(pkin))
    except ValueError:
        getpk = uuid.UUID(ensure_str(pkin))
    obj = await klass.get(getpk)
    click.echo(json.dumps(obj.to_dict(), cls=DBTypesEncoder))


async def create_and_print_json(klass: Type[BaseModel], init_kwargs: Dict[str, Any]) -> None:
    """helper to create and dump as JSON object of type klass with init args from init_kwargs"""
    obj = klass(**init_kwargs)
    await obj.create()
    click.echo(json.dumps(obj.to_dict(), cls=DBTypesEncoder))


async def list_and_print_json(klass: Type[BaseModel]) -> None:
    """helper to list and dump as JSON all objects of type klass"""
    dbobjs = await models.db.all(klass.query)
    ret: List[Dict[str, Any]] = []
    for dbobj in dbobjs:
        ret.append(dbobj.to_dict())
    click.echo(json.dumps(ret, cls=DBTypesEncoder))


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
