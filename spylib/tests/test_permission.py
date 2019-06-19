from __future__ import absolute_import
from ..permission import has_permission
import unittest
import jwt
import uuid
import datetime


class TestPermission(unittest.TestCase):
    def test_no_services_has_no_permission(self):
        algorithm = "HS256"
        secret = "1234"
        access_token = jwt.encode({"test": "test"}, secret, algorithm).decode("utf-8")
        assert not has_permission(access_token, "", "", algorithm, secret)

    def test_has_permission_success(self):
        algorithm = "HS256"
        secret = "1234"
        test_uuid = uuid.uuid4()
        access_token = jwt.encode(
            {"services": {str(test_uuid): ["allurbasebelong2us"]}}, secret, algorithm
        ).decode("utf-8")
        assert has_permission(
            access_token, str(test_uuid), "allurbasebelong2us", algorithm, secret
        )

    def test_has_permission_fails(self):
        algorithm = "HS256"
        secret = "1234"
        test_uuid = uuid.uuid4()
        access_token = jwt.encode(
            {"services": {str(test_uuid): ["allurbasebelong2us"]}}, secret, algorithm
        ).decode("utf-8")
        assert not has_permission(
            access_token, str(uuid.uuid4()), "allurbasebelong2us", algorithm, secret
        )

    def test_expired_signature_error_raises(self):
        algorithm = "HS256"
        secret = "1234"
        test_uuid = uuid.uuid4()
        access_token = jwt.encode(
            {
                "exp": datetime.datetime.now() + datetime.timedelta(-30),
                "services": {str(test_uuid): ["allurbasebelong2us"]},
            },
            secret,
            algorithm,
        ).decode("utf-8")
        with self.assertRaises(jwt.exceptions.ExpiredSignatureError):
            has_permission(
                access_token, uuid.uuid4(), "allurbasebelong2us", algorithm, secret
            )
