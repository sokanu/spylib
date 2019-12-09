from __future__ import absolute_import
from .auth_client import AuthClient
import unittest
import os
import responses

JWT_SECRET = "1234"
JWT_ALGORITHM = "HS256"


class TestAuthClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["SPYLIB_AUTH_BASE_URL"] = "https://auth.localhost:8000"

    @responses.activate
    def test_create_entity_makes_call(self):
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/entities", status=201
        )
        auth_client = AuthClient()
        resp = auth_client.create_entity()
        assert resp == 201
        assert responses.calls.__len__() == 1
