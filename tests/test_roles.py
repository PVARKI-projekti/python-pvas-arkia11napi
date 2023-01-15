"""Test role endpoint stuff"""
from typing import AsyncGenerator, List
import logging
import asyncio

import pytest
import pytest_asyncio
from libadvian.binpackers import uuid_to_b64, b64_to_uuid
from async_asgi_testclient import TestClient

from arkia11nmodels.models.role import Role, UserRole
from arkia11nmodels.schemas.role import DBRole, RoleCreate
from arkia11napi.api import WRAPPER

# pylint: disable=W0621
LOGGER = logging.getLogger(__name__)


@pytest_asyncio.fixture(scope="module")
async def three_roles(dockerdb: str) -> AsyncGenerator[List[Role], None]:
    """Create three roles and yield them, then nuke"""
    _ = dockerdb
    await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
    admins = Role(
        displayname="Test: SuperAdmins",
        acl=[
            {
                "privilege": "fi.pvarki.superadmin",
                "action": True,
            }
        ],
    )
    await admins.create()
    takadmins = Role(
        displayname="Test: TAK admins",
        acl=[
            {
                "privilege": "fi.pvarki.takserver:admin",
                "target": "someserver.arki.fi",
                "action": True,
            }
        ],
    )
    await takadmins.create()
    takusers = Role(
        displayname="Test: TAK users",
        acl=[
            {
                "privilege": "fi.pvarki.takserver:user",
                "target": "someserver.arki.fi:self",
                "action": True,
            }
        ],
    )
    await takusers.create()
    # Refresh the objects from DB and yield
    ret: List[Role] = []
    for role in (admins, takadmins, takusers):
        ret.append(await Role.get(role.pk))
    yield ret

    for role in ret:
        await WRAPPER.bind_gino(asyncio.get_event_loop())  # whyyy ?
        await UserRole.delete.where(UserRole.role == role.pk).gino.status()  # Nuke leftovers
        await role.delete()


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
async def test_create_delete(client: TestClient) -> None:
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
