"""Mailer related tests"""
import logging

import pytest
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
