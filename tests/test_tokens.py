"""Test token endpoints"""
from typing import Any
import logging
import re

import pytest
from libadvian.binpackers import ensure_str, b64_to_uuid
from async_asgi_testclient import TestClient
from arkia11nmodels.models import User


import arkia11napi.mailer
from arkia11napi.config import TOKEN_EMAIL_SUBJECT, JWT_COOKIE_NAME
import arkia11napi.config
import arkia11napi.views.tokens

# pylint: disable=W0621
LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_request_token_email(unauth_client: TestClient, enduser_object: User) -> None:
    """Test tokens get emailed"""
    mailer = arkia11napi.mailer.singleton()
    with mailer.record_messages() as outbox:
        resp = await unauth_client.post(
            "/api/v1/tokens",
            json={
                "deliver_via": "email",
                "target": enduser_object.email,
            },
        )
        LOGGER.debug("resp={}, content={}".format(resp, resp.content))
        assert resp.status_code == 201
        assert len(outbox) == 1
        msg = outbox[0]
        assert msg["subject"] == TOKEN_EMAIL_SUBJECT
        # Fscking MIME...
        payload = outbox[0].get_payload(0).get_payload(decode=True)
        assert "/api/v1/tokens/use" in ensure_str(payload)


@pytest.mark.asyncio
async def test_request_token_email_urloverride(
    unauth_client: TestClient, enduser_object: User, monkeypatch: Any
) -> None:
    """Test tokens get emailed with overridden url"""
    url_override = "https://foo.bar.baz/"
    monkeypatch.setenv("TOKEN_URL_OVERRIDE", url_override)
    monkeypatch.setattr(arkia11napi.config, "TOKEN_URL_OVERRIDE", url_override)
    monkeypatch.setattr(arkia11napi.views.tokens, "TOKEN_URL_OVERRIDE", url_override)
    mailer = arkia11napi.mailer.singleton()
    with mailer.record_messages() as outbox:
        resp = await unauth_client.post(
            "/api/v1/tokens",
            json={
                "deliver_via": "email",
                "target": enduser_object.email,
            },
        )
        LOGGER.debug("resp={}, content={}".format(resp, resp.content))
        assert resp.status_code == 201
        assert len(outbox) == 1
        msg = outbox[0]
        assert msg["subject"] == TOKEN_EMAIL_SUBJECT
        # Fscking MIME...
        payload = outbox[0].get_payload(0).get_payload(decode=True)
        assert url_override in ensure_str(payload)


@pytest.mark.asyncio
async def test_request_token_sms(unauth_client: TestClient, enduser_object: User) -> None:
    """Test tokens (do not) get smsed"""
    resp = await unauth_client.post(
        "/api/v1/tokens",
        json={
            "deliver_via": "sms",
            "target": enduser_object.sms,
        },
    )
    LOGGER.debug("resp={}, content={}".format(resp, resp.content))
    assert resp.status_code == 201
    payload = resp.json()
    # We do not support SMS yet
    assert payload["sent"] is False


@pytest.mark.asyncio
async def test_use_token_defaultredirect(unauth_client: TestClient, enduser_object: User) -> None:
    """Test token use"""
    mailer = arkia11napi.mailer.singleton()
    with mailer.record_messages() as outbox:
        resp_create = await unauth_client.post(
            "/api/v1/tokens",
            json={
                "deliver_via": "email",
                "target": enduser_object.email,
            },
        )
        LOGGER.debug("resp_create={}, content={}".format(resp_create, resp_create.content))
        assert resp_create.status_code == 201
        assert len(outbox) == 1
        msg = outbox[0]
        assert msg["subject"] == TOKEN_EMAIL_SUBJECT
        # Fscking MIME...
        email_body = ensure_str(outbox[0].get_payload(0).get_payload(decode=True))
        assert "/api/v1/tokens/use" in email_body
        LOGGER.debug("email_body={}".format(email_body))
        match = re.search(r"\s(?P<url>https?://[^/]+(?P<path>\S+)\?token=(?P<token>\S+))\s", email_body)
        LOGGER.debug("match={}".format(match))
        if not match:
            raise RuntimeError("Could not parse token/url")
        token_uuid = b64_to_uuid(match.group("token"))
        assert token_uuid

        get_url = f"{match.group('path')}?token={match.group('token')}"
        LOGGER.debug("GETting url {}".format(get_url))
        resp_use = await unauth_client.get(get_url, allow_redirects=False)
        LOGGER.debug("resp_use={}, .content={}".format(resp_use, resp_use.content))

        assert resp_use.status_code == 303
        assert JWT_COOKIE_NAME in resp_use.cookies
        assert resp_use.headers["location"].endswith("/api/v1/users/me")


@pytest.mark.asyncio
async def test_use_token_customredirect(unauth_client: TestClient, enduser_object: User) -> None:
    """Test token use"""
    mailer = arkia11napi.mailer.singleton()
    with mailer.record_messages() as outbox:
        resp_create = await unauth_client.post(
            "/api/v1/tokens",
            json={
                "deliver_via": "email",
                "target": enduser_object.email,
                "redirect": "https://customurl.example.com",
            },
        )
        LOGGER.debug("resp_create={}, content={}".format(resp_create, resp_create.content))
        assert resp_create.status_code == 201
        assert len(outbox) == 1
        msg = outbox[0]
        assert msg["subject"] == TOKEN_EMAIL_SUBJECT
        # Fscking MIME...
        email_body = ensure_str(outbox[0].get_payload(0).get_payload(decode=True))
        assert "/api/v1/tokens/use" in email_body
        LOGGER.debug("email_body={}".format(email_body))
        match = re.search(r"\s(?P<url>https?://[^/]+(?P<path>\S+)\?token=(?P<token>\S+))\s", email_body)
        LOGGER.debug("match={}".format(match))
        if not match:
            raise RuntimeError("Could not parse token/url")
        token_uuid = b64_to_uuid(match.group("token"))
        assert token_uuid

        get_url = f"{match.group('path')}?token={match.group('token')}"
        LOGGER.debug("GETting url {}".format(get_url))
        resp_use = await unauth_client.get(get_url, allow_redirects=False)
        LOGGER.debug("resp_use={}, .content={}".format(resp_use, resp_use.content))

        assert resp_use.status_code == 303
        assert JWT_COOKIE_NAME in resp_use.cookies
        assert resp_use.headers["location"].startswith("https://customurl.example.com")
