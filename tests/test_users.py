""""Test user endpoints"""
from typing import List
import logging

import pytest
from libadvian.binpackers import uuid_to_b64, b64_to_uuid
from async_asgi_testclient import TestClient

from arkia11nmodels.models.user import User
from arkia11nmodels.schemas.user import DBUser, UserCreate

# pylint: disable=W0621
LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_list_users_unauth(unauth_client: TestClient) -> None:
    """Test we can't get users listed"""
    resp = await unauth_client.get("/api/v1/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_users_enduser(enduser_client: TestClient) -> None:
    """Test we can't get users listed as end-user"""
    resp = await enduser_client.get("/api/v1/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_users(client: TestClient, three_users: List[User]) -> None:
    """Test we can get users listed"""
    user1, user2, user3 = three_users
    resp = await client.get("/api/v1/users")
    assert resp.status_code == 200
    payload = resp.json()
    dnames = [item["displayname"] for item in payload["items"]]
    assert user1.displayname in dnames
    assert user2.displayname in dnames
    assert user3.displayname in dnames


@pytest.mark.asyncio
async def test_get_users(client: TestClient, three_users: List[User]) -> None:
    """Test we can get a given user by both UUID formats"""
    for user in three_users:
        resp = await client.get(f"/api/v1/users/{uuid_to_b64(user.pk)}")  # type: ignore # false positive
        assert resp.status_code == 200
        resp2 = await client.get(f"/api/v1/users/{str(user.pk)}")
        assert resp2.status_code == 200
        pljson = resp.json()
        pljson["pk"] = b64_to_uuid(pljson["pk"])
        payload = DBUser.parse_obj(pljson)
        assert payload.displayname == user.displayname


@pytest.mark.asyncio
async def test_create_delete_user(client: TestClient) -> None:
    """Test that we can create and delete user"""
    user_email = "http_api_create@example.com"

    resp0 = await client.get("/api/v1/users")
    assert resp0.status_code == 200
    pl0 = resp0.json()
    LOGGER.debug("pl0={}".format(pl0))
    assert user_email not in [item["email"] for item in pl0["items"]]

    cuser = UserCreate(email=user_email)
    LOGGER.debug("POSTing {cuser.dict()}")
    resp = await client.post("/api/v1/users", json=cuser.dict())
    LOGGER.debug("got response: {resp}")
    assert resp.status_code == 201
    pljson = resp.json()
    pljson["pk"] = b64_to_uuid(pljson["pk"])
    payload = DBUser.parse_obj(pljson)
    assert payload.displayname == user_email

    # Delete
    resp2 = await client.delete(f"/api/v1/users/{str(payload.pk)}")
    assert resp2.status_code == 204

    # Re-fetch (should fail)
    resp3 = await client.get(f"/api/v1/users/{str(payload.pk)}")
    assert resp3.status_code == 404
