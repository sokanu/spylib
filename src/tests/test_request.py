from __future__ import absolute_import
from ..request import Request
from ..exceptions import RefreshException
import datetime
import jwt
import unittest


class TestRequest(unittest.TestCase):
    def test_init_with_good_access_token_success(self):
        """
        Given:
            - a good access token
            - a base url
            - a secret
            - an algorithm
        When:
            - a request object is built.
        Outcome:
            - all fields are set and refresh token is None
        """
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode({"test": "test"}, "1234", "HS256").decode("utf-8")
        req = Request(
            "localhost:8000",
            access_token=access_token,
            secret=secret,
            algorithm=algorithm,
        )
        assert req.access_token == access_token
        assert req.base_url == "localhost:8000"
        assert req.secret
        assert req.base_url
        assert req.refresh_token is None

    def test_init_with_good_access_and_refresh_token_success(self):
        """
        Given:
            - a good access and refresh token
            - a base url
            - a secret
            - an algorithm.
        When:
            - a request object is built
        Outcome:
            - all fields are set.
        """
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode({}, secret, algorithm=algorithm).decode("utf-8")
        req = Request(
            "localhost:8000",
            access_token=access_token,
            algorithm=algorithm,
            secret=secret,
            refresh_token="billy",
        )
        assert req.access_token == access_token
        assert req.base_url == "localhost:8000"
        assert req.secret
        assert req.base_url
        assert req.refresh_token == "billy"

    def test_init_with_bad_access_no_refresh_token_throws_exception(self):
        """
        Given:
            - a bad access token
            - a base url
            - a secret
            - an algorithm
            - no refresh token.
        When:
            - a request object is built.
        Outcome:
            - throws a RefreshException
        """
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(-30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        with self.assertRaises(RefreshException):
            Request(
                "localhost:8000",
                access_token=access_token,
                algorithm=algorithm,
                secret=secret,
            )

    def test_init_with_good_access_no_refresh_token_throws_exception(self):
        """
        Given:
            - a bad access token
            - a base url
            - a secret
            - an algorithm
            - no refresh token.
        When:
            - a request object is built.
        Outcome:
            - throws a RefreshException
        """
        pass
