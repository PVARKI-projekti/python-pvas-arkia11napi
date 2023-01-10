"""Main API entrypoint"""
from typing import Mapping
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from .views.tokens import TOKEN_ROUTER
from .views.roles import ROLE_ROUTER
from .views.users import USER_ROUTER

STATIC_PATH = Path(__file__).parent / "staticfiles"
TEMPLATES_PATH = Path(__file__).parent / "templates"

APP = FastAPI(docs_url="/api/docs", openapi_url="/api/openapi.json")
APP.mount("/static", StaticFiles(directory=str(STATIC_PATH)), name="static")
TEMPLATES = Jinja2Templates(directory=str(TEMPLATES_PATH))
APP.include_router(ROLE_ROUTER)
APP.include_router(USER_ROUTER)
APP.include_router(TOKEN_ROUTER)


@APP.get("/gdpr", tags=["privacy"], response_class=HTMLResponse)
async def show_gdpr(request: Request) -> Response:
    """Show the GDPR info as HTML"""
    return TEMPLATES.TemplateResponse(
        "gdpr.html",
        {
            "request": request,
            # FIXME: Add any config variables the template needs here
        },
    )


@APP.get("/api/v1", tags=["misc"])
async def hello() -> Mapping[str, str]:
    """Say hello"""
    return {"message": "Hello World"}
