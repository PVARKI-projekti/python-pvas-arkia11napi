"""Test role endpoint stuff"""
from typing import List
import logging

import pytest
from libadvian.binpackers import uuid_to_b64, b64_to_uuid
from async_asgi_testclient import TestClient

from arkia11nmodels.models import Role, User
from arkia11nmodels.schemas.role import DBRole, RoleCreate

# pylint: disable=W0621
LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_list_roles_unauth(unauth_client: TestClient) -> None:
    """Test we can't get roles listed"""
    resp = await unauth_client.get("/api/v1/roles")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_roles_enduser(enduser_client: TestClient) -> None:
    """Test we can't get roles listed as end-user"""
    resp = await enduser_client.get("/api/v1/roles")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_roles(client: TestClient, three_roles: List[Role]) -> None:
    """Test we can get roles listed"""
    admins, tak_admins, tak_users = three_roles
    resp = await client.get("/api/v1/roles")
    assert resp.status_code == 200
    payload = resp.json()
    dnames = [item["displayname"] for item in payload["items"]]
    assert admins.displayname in dnames
    assert tak_admins.displayname in dnames
    assert tak_users.displayname in dnames


@pytest.mark.asyncio
async def test_get_roles(client: TestClient, three_roles: List[Role]) -> None:
    """Test we can get a given role by both UUID formats"""
    for role in three_roles:
        resp = await client.get(f"/api/v1/roles/{uuid_to_b64(role.pk)}")  # type: ignore # false positive
        assert resp.status_code == 200
        resp2 = await client.get(f"/api/v1/roles/{str(role.pk)}")
        assert resp2.status_code == 200
        pljson = resp.json()
        pljson["pk"] = b64_to_uuid(pljson["pk"])
        payload = DBRole.parse_obj(pljson)
        assert payload.displayname == role.displayname


@pytest.mark.asyncio
async def test_create_delete_role(client: TestClient) -> None:
    """Test that we can create and delete role"""
    crole = RoleCreate(displayname="Test: HTTP API create test")
    resp = await client.post("/api/v1/roles", json=crole.dict())
    assert resp.status_code == 201
    pljson = resp.json()
    pljson["pk"] = b64_to_uuid(pljson["pk"])
    payload = DBRole.parse_obj(pljson)
    assert payload.displayname == "Test: HTTP API create test"

    # Delete
    resp2 = await client.delete(f"/api/v1/roles/{str(payload.pk)}")
    assert resp2.status_code == 204

    # Re-fetch (should fail)
    resp3 = await client.get(f"/api/v1/roles/{str(payload.pk)}")
    assert resp3.status_code == 404


@pytest.mark.asyncio
async def test_assign_via_role(client: TestClient, three_roles: List[Role], three_users: List[User]) -> None:
    """Test role assignment from roles side"""
    # pylint: disable=R0914
    _admins, tak_admins, _tak_users = three_roles
    _user1, user2, user3 = three_users

    # Assign role to user
    resp1 = await client.post(f"/api/v1/roles/{str(tak_admins.pk)}/users", json=[str(user2.pk), str(user3.pk)])
    assert resp1.status_code == 200
    pl1 = resp1.json()
    assert isinstance(pl1, list)
    dnames1 = [item["displayname"] for item in pl1]
    assert user2.displayname in dnames1
    assert user3.displayname in dnames1

    # List users with role and make sure the added one is among them
    resp2 = await client.get(f"/api/v1/roles/{str(tak_admins.pk)}/users")
    assert resp2.status_code == 200
    pl2 = resp2.json()
    dnames2 = [item["displayname"] for item in pl2["items"]]
    assert user2.displayname in dnames2

    # un-assign
    resp3 = await client.delete(f"/api/v1/roles/{str(tak_admins.pk)}/users/{str(user2.pk)}")
    assert resp3.status_code == 204

    # List users with role and make sure the added one is not among them
    resp4 = await client.get(f"/api/v1/roles/{str(tak_admins.pk)}/users")
    assert resp4.status_code == 200
    pl4 = resp4.json()
    dnames3 = [item["displayname"] for item in pl4["items"]]
    assert user2.displayname not in dnames3
    assert user3.displayname in dnames3

    # un-assign
    resp5 = await client.delete(f"/api/v1/roles/{str(tak_admins.pk)}/users/{str(user3.pk)}")
    assert resp5.status_code == 204
