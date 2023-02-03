"""Test token endpoints"""
import logging

import pytest
from libadvian.binpackers import ensure_str
from async_asgi_testclient import TestClient
from arkia11nmodels.models import User

import arkia11napi.mailer
from arkia11napi.config import TOKEN_EMAIL_SUBJECT


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
