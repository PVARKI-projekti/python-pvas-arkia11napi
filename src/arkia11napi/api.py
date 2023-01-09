"""Main API entrypoint"""
from typing import Mapping

from fastapi import FastAPI

from .views.tokens import TOKEN_ROUTER
from .views.roles import ROLE_ROUTER

APP = FastAPI(docs_url="/api/docs", openapi_url="/api/openapi.json")
APP.include_router(TOKEN_ROUTER)
APP.include_router(ROLE_ROUTER)


@APP.get("/api/v1")
async def hello() -> Mapping[str, str]:
    """Say hello"""
    return {"message": "Hello World"}
