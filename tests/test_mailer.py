"""Mailer related tests"""
import logging

import pytest
from libadvian.binpackers import ensure_str
from fastapi_mail import MessageSchema, MessageType


import arkia11napi.mailer

LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_send() -> None:
    """Trivial send test just for smoketesting"""
    mailer = arkia11napi.mailer.singleton()
    with mailer.record_messages() as outbox:
        msg = MessageSchema(
            subject="Testing", recipients=["test_target@example.com"], subtype=MessageType.plain, body="Hello World!"
        )
        await mailer.send_message(msg)
        assert len(outbox) == 1
        assert outbox[0]["To"] == "test_target@example.com"
        assert outbox[0]["from"] == "testsender@example.com"


@pytest.mark.asyncio
async def test_template() -> None:
    """Trivial send test just for smoketesting templates"""
    magic_str = "MAGIC_FIND_ME_MAGIC"
    mailer = arkia11napi.mailer.singleton()
    with mailer.record_messages() as outbox:
        msg = MessageSchema(
            subject="Testing",
            recipients=["test_target@example.com"],
            subtype=MessageType.plain,
            body="Hello World!",
            template_body={"login_url": magic_str},
        )
        await mailer.send_message(msg, template_name="token_email.txt")
        assert len(outbox) == 1
        LOGGER.debug("outbox[0]={}".format(repr(outbox[0])))
        assert outbox[0]["To"] == "test_target@example.com"
        assert outbox[0]["from"] == "testsender@example.com"
        # Fscking MIME...
        payload = outbox[0].get_payload(0).get_payload(decode=True)
        LOGGER.debug("payload={}".format(repr(payload)))
        assert magic_str in ensure_str(payload)
