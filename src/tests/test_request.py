from __future__ import absolute_import
from ..request import Request
from ..exceptions import RefreshException, LoginException
import datetime
import json
import jwt
import unittest
import responses


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

    def test_bad_access_token_no_refresh_token_throws_exception(self):
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

    @responses.activate
    def test_bad_access_no_refresh_token_server_throws_exception(self):
        """
        Given:
            - a bad access token
            - a base url
            - a secret
            - an algorithm
            - no refresh token.
            - a mocked refresh endpoint that fails.
        When:
            - a request obj built and server fails with a non 200 status code.
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
        responses.add(
            responses.POST, "https://localhost:8000/api/v1/tokens", status=500
        )
        with self.assertRaises(RefreshException):
            Request(
                "https://localhost:8000",
                access_token=access_token,
                algorithm=algorithm,
                secret=secret,
            )

    @responses.activate
    def test_login_raises_login_exception_on_failure(self):
        """
        Given:
            - no tokens
            - a bad response.
        When:
            - login called
        Outcome:
            - LoginException raised.

        """
        responses.add(responses.POST, "https://localhost:8000/api/v1/login", status=500)
        with self.assertRaises(LoginException):
            Request("https://localhost:8000").login("fake", "fake")

    @responses.activate
    def test_login_succeeds_when_server_201(self):
        """
        Given:
            - no tokens.
            - a good response.
        When:
            - login called
        Outcome:
            - LoginException raised.

        """

        def request_callback(request):
            resp_body = {"access_token": "5678"}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (200, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://localhost:8000/api/v1/login",
            callback=request_callback,
            content_type="application/json",
        )
        resp = Request("https://localhost:8000").login("fake", "fake")

        assert resp.get("access_token") == "5678"
        assert resp.get("refresh_token") == "1234"
