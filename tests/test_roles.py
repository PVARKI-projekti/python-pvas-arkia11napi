"""Test role endpoint stuff"""
import logging

import pytest
from fastapi.testclient import TestClient

LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_list_roles(client: TestClient) -> None:
    """Test we can get roles listed"""
    # TODO: add some roles and make sure we get them
    resp = client.get("/api/v1/roles")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_roles_unauth(unauth_client: TestClient) -> None:
    """Test we can get roles listed"""
    # TODO: add some roles and make sure we get them
    resp = unauth_client.get("/api/v1/roles")
    assert resp.status_code == 403
