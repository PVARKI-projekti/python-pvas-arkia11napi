"""General helpers"""
from typing import Type, Union, cast
import logging
import uuid

from starlette import status
from starlette.exceptions import HTTPException
from libadvian.binpackers import b64_to_uuid, ensure_utf8, ensure_str
from arkia11nmodels.models.base import BaseModel

LOGGER = logging.getLogger(__name__)


# FIXME: this should probably be in some common library of ours
async def get_or_404(klass: Type[BaseModel], pkin: Union[bytes, str]) -> BaseModel:
    """Get a db object by its klass and UUID (base64 or hex str)"""
    try:
        getpk = b64_to_uuid(ensure_utf8(pkin))
    except ValueError:
        getpk = uuid.UUID(ensure_str(pkin))
    obj = await klass.get(getpk)
    if not obj:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "{} not found with pk {}".format(klass.__name__, ensure_str(pkin)),
        )
    return cast(BaseModel, obj)
