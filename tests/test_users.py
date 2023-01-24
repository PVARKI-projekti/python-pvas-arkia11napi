""""Test user endpoints"""
from typing import List
import logging

import pytest
from libadvian.binpackers import uuid_to_b64, b64_to_uuid
from async_asgi_testclient import TestClient

from arkia11nmodels.models import User, Role
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


@pytest.mark.asyncio
async def test_assign_via_user(client: TestClient, three_roles: List[Role], three_users: List[User]) -> None:
    """Test role assignment from users side"""
    # pylint: disable=R0914
    admins, _tak_admins, tak_users = three_roles
    user1, _user2, _user3 = three_users

    # Assign user two roles
    resp1 = await client.post(f"/api/v1/users/{str(user1.pk)}/roles", json=[str(admins.pk), str(tak_users.pk)])
    assert resp1.status_code == 200
    pl1 = resp1.json()
    assert isinstance(pl1, list)
    dnames1 = [item["displayname"] for item in pl1]
    assert admins.displayname in dnames1
    assert tak_users.displayname in dnames1

    # List roles of user
    resp2 = await client.get(f"/api/v1/users/{str(user1.pk)}/roles")
    assert resp2.status_code == 200
    pl2 = resp2.json()
    dnames2 = [item["displayname"] for item in pl2]
    assert tak_users.displayname in dnames2
    assert admins.displayname in dnames2

    # un-assign
    resp3 = await client.delete(f"/api/v1/users/{str(user1.pk)}/roles/{str(tak_users.pk)}")
    assert resp3.status_code == 204

    # List users with role and make sure the added one is not among them
    resp4 = await client.get(f"/api/v1/users/{str(user1.pk)}/roles")
    assert resp4.status_code == 200
    pl4 = resp4.json()
    dnames3 = [item["displayname"] for item in pl4]
    assert tak_users.displayname not in dnames3
    assert admins.displayname in dnames3

    # un-assign
    resp5 = await client.delete(f"/api/v1/users/{str(user1.pk)}/roles/{str(admins.pk)}")
    assert resp5.status_code == 204
