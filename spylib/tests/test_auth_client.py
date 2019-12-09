from __future__ import absolute_import
from spylib.auth_client import AuthClient
import uuid
import unittest
import os
import responses
import json


JWT_SECRET = "1234"
JWT_ALGORITHM = "HS256"


class TestAuthClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["SPYLIB_AUTH_BASE_URL"] = "https://auth.localhost:8000"

    @responses.activate
    def test_create_entity_makes_call(self):
        def request_callback(request):
            resp_body = {}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (201, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/entities",
            callback=request_callback,
            content_type="application/json",
        )
        auth_client = AuthClient()
        auth_client.create_entity()
        assert responses.calls.__len__() == 1

    @responses.activate
    def test_create_entity_api_key_makes_call(self):
        def request_callback(request):
            resp_body = {}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (201, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/entity-api-keys",
            callback=request_callback,
            content_type="application/json",
        )
        auth_client = AuthClient()
        auth_client.create_entity_api_key(uuid.uuid4())
        assert responses.calls.__len__() == 1

    @responses.activate
    def test_create_auth_perm_makes_call(self):
        def request_callback(request):
            resp_body = {}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (201, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/permissions",
            callback=request_callback,
            content_type="application/json",
        )
        auth_client = AuthClient()
        auth_client.create_auth_perm(
            uuid.uuid4(), "test_perm", "a description used for testing"
        )
        assert responses.calls.__len__() == 1

    @responses.activate
    def test_associate_entity_with_perm_makes_call(self):
        def request_callback(request):
            resp_body = {"status_code": 201}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (201, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/entity-permissions",
            callback=request_callback,
            content_type="application/json",
        )
        auth_client = AuthClient()
        auth_client.associate_entity_with_permission(
            uuid.uuid4(), "test_perm", "a description used for testing"
        )
        assert responses.calls.__len__() == 1

    @responses.activate
    def test_deassociate_entity_with_perm_makes_call(self):
        def request_callback(request):
            resp_body = {"status_code": 200}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (200, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.DELETE,
            "https://auth.localhost:8000/api/v1/entity-permissions",
            callback=request_callback,
            content_type="application/json",
        )
        auth_client = AuthClient()
        auth_client.deassociate_entity_with_permission(
            uuid.uuid4(), "test_perm", "a description used for testing"
        )
        assert responses.calls.__len__() == 1
