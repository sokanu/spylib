from __future__ import absolute_import
from ..request import ServiceRequestFactory
from ..exceptions import LoginException
import uuid
import datetime
import json
import jwt
import unittest
import responses
import os


class TestServiceRequestFactory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["SPYLIB_AUTH_BASE_URL"] = "https://auth.localhost:8000"

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
        req = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=secret,
            algorithm=algorithm,
        )
        assert req.access_token == access_token
        assert req.secret
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
        req = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            algorithm=algorithm,
            secret=secret,
            refresh_token="billy",
        )
        assert req.access_token == access_token
        assert req.secret
        assert req.refresh_token == "billy"

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
            - a mocked login endpoint that fails.
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
            responses.POST, "https://auth.localhost:8000/api/v1/tokens", status=500
        )
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/login", status=500
        )
        with self.assertRaises(LoginException):
            ServiceRequestFactory(
                uuid=str(uuid.uuid4()),
                api_key="1234",
                access_token=access_token,
                algorithm=algorithm,
                secret=secret,
            )

    @responses.activate
    def test_refresh_token_gets_new_access_token_success(self):
        """
        Given:
            - an access token
            - a mocked URL returning a 201 from the refresh token endpoint.
            - a refresh token.
        When:
            - Refresh token endpoint succeeds.
        Outcome:
            - the request object has the response from the mocked url.
        """
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(-30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            body=json.dumps({"access_token": "1234"}),
        )
        res = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            algorithm=algorithm,
            secret=secret,
            refresh_token="1234",
        )
        assert res.access_token == "1234"

    @responses.activate
    def test_login_raises_login_exception_on_failure(self):
        """
        Given:
            - no tokens
            - a bad response from login.
        When:
            - service object is created
        Outcome:
            - LoginException raised because the tokens dont exist, and login fallback fails.
        """
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/login", status=500
        )
        with self.assertRaises(LoginException):
            ServiceRequestFactory(uuid="fake", api_key="fake")

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
            "https://auth.localhost:8000/api/v1/login",
            callback=request_callback,
            content_type="application/json",
        )
        req = ServiceRequestFactory(uuid="fake", api_key="fake")
        assert req.access_token == "5678"
        assert req.refresh_token == "1234"

    @responses.activate
    def test_make_service_request_doesnt_retry_on_unexpired_token(self):
        """
        Given:
            - retry option is configured to retry once.
            - a bad response from the test endpoint - that's a 500
        When:
            - a make service request is executed
        Outcome:
            - two calls to the mock responses are made.
        """

        def request_callback(request):
            resp_body = {}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (500, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/test",
            callback=request_callback,
            content_type="application/json",
        )
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=secret,
            algorithm=algorithm,
        )
        resp.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="POST",
            payload={},
            retry_count=1,
        )
        assert responses.calls.__len__() == 2

    @responses.activate
    def test_make_service_request_retries_successfully(self):
        """
        Given:
            - retry option is configured to retry once.
            - refresh token is provided.
            - a bad response of 401 is configured on the mock response.
            - override access token on initialized object, and provide a bad access token.
        When:
            - a make service request is executed
        Outcome:
            - expect a retry to occur twice.
            - expect a refresh to be called once.
        """

        def request_callback(request):
            resp_body = {}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (401, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/test",
            callback=request_callback,
            content_type="application/json",
        )
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            body=json.dumps({"access_token": "1234"}),
        )

        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=secret,
            algorithm=algorithm,
        )
        # override access token with an 'old' one.
        resp.access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(-30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp.refresh_token = "1234"
        resp.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="POST",
            payload={},
            retry_count=1,
        )
        assert responses.calls.__len__() == 3

    @responses.activate
    def test_make_service_request_no_retr_succeeds(self):
        """
        Given:
            - a bad response that's a 500
            - no retry set.
        When:
            - a make service request is executed
        Outcome:
            - one call to the mock responses are made.
        """

        def request_callback(request):
            resp_body = {}
            headers = {"set-cookie": "refresh_token=1234;"}
            return (500, headers, json.dumps(resp_body))

        responses.add_callback(
            responses.POST,
            "https://auth.localhost:8000/api/v1/test",
            callback=request_callback,
            content_type="application/json",
        )
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=secret,
            algorithm=algorithm,
        )
        resp.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="POST",
            retry_count=0,
            payload={},
        )
        assert responses.calls.__len__() == 1

    @responses.activate
    def test_make_service_request_raises_with_expired_token_and_no_refresh_token(self):
        """
        Given:
            - an expired access token.
            - no refresh token.
            - a 401 response from the server.
        When:
            - a make service request is executed
        Outcome:
            - LoginError occurs since no token can be obtained upon the login fallback.
        """
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=secret,
            algorithm=algorithm,
        )
        # override the token with a bad one.
        resp.access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(-30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")

        # order here matters. matching urls will be hit in the order declared.
        responses.add(
            responses.GET,
            "https://auth.localhost:8000/api/v1/test",
            status=401,
            json={},
        )
        responses.add(
            responses.GET,
            "https://auth.localhost:8000/api/v1/test",
            status=200,
            json={"is_hit": True},
        )
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            json={"access_token": "1234"},
        )
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/login", status=500
        )
        with self.assertRaises(LoginException):
            resp.make_service_request(
                "https://auth.localhost:8000",
                path="/api/v1/test",
                method="GET",
                retry_count=1,
                payload={},
            )

    @responses.activate
    def test_make_service_request_with_expired_token(self):
        """
        Given:
            - an expired access token.
            - a valid refresh token.
            - a 401 response from the server.
        When:
            - a make service request is executed
        Outcome:
            - a new access token is set.
            - the response from the test server is retrieved.
        """
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            refresh_token="1a2a3a",
            secret=secret,
            algorithm=algorithm,
        )
        # override the token with a bad one.
        resp.access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(-30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")

        # order here matters. matching urls will be hit in the order declared.
        responses.add(
            responses.GET,
            "https://auth.localhost:8000/api/v1/test",
            status=401,
            json={},
        )
        responses.add(
            responses.GET,
            "https://auth.localhost:8000/api/v1/test",
            status=200,
            json={"is_hit": True},
        )
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            json={"access_token": "1234"},
        )

        res = resp.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="GET",
            retry_count=1,
            payload={},
        )
        assert res.json().get("is_hit", False)

    @responses.activate
    def test_make_service_request_delete_payload_succeeds(self):
        """
        Given:
            - valid access token
            - a mock payload to delete
        When:
            - a make service request is executed.
        Outcome:
            - a 200 is returned
        """
        responses.add(
            responses.DELETE, "https://auth.localhost:8000/api/v1/test", status=200
        )
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            refresh_token="1a2a3a",
            secret=secret,
            algorithm=algorithm,
        )
        res = resp.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="DELETE",
            retry_count=0,
        )
        assert res.status_code == 200

    @responses.activate
    def test_make_service_request_patch_payload_succeeds(self):
        """
        Given:
            - valid access token
            - a mock endpoint to hit with PATCH method.
        When:
            - a make service request is executed.
        Outcome:
            - a 200 is returned
        """
        responses.add(
            responses.PATCH, "https://auth.localhost:8000/api/v1/test", status=200
        )
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            refresh_token="1a2a3a",
            secret=secret,
            algorithm=algorithm,
        )
        res = resp.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="PATCH",
            retry_count=0,
            payload={"test": "test"},
        )
        assert res.status_code == 200

    @responses.activate
    def test_make_service_request_put_payload_succeeds(self):
        """
        Given:
            - valid access token
            - a mock endpoint to hit with PUT method.
        When:
            - a make service request is executed.
        Outcome:
            - a 200 is returned
        """
        responses.add(
            responses.PUT, "https://auth.localhost:8000/api/v1/test", status=201
        )
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            refresh_token="1a2a3a",
            secret=secret,
            algorithm=algorithm,
        )
        res = resp.make_service_request(
            "https://auth.localhost:8000",
            "/api/v1/test",
            method="PUT",
            retry_count=0,
            payload={"test": "test"},
        )
        assert res.status_code == 201

    def test_get_tokens_dict(self):
        secret = "1234"
        algorithm = "HS256"
        access_token = jwt.encode(
            {"exp": datetime.datetime.now() + datetime.timedelta(30)},
            secret,
            algorithm=algorithm,
        ).decode("utf-8")
        req_obj = ServiceRequestFactory(
            "1234",
            "4321",
            access_token=access_token,
            refresh_token="321",
            secret=secret,
            algorithm=algorithm,
        )
        token_dict = req_obj.get_tokens_dict()
        assert token_dict.get("access_token") == access_token
        assert token_dict.get("refresh_token") == "321"

    def test_url_join_https(self):
        assert (
            ServiceRequestFactory.urljoin("https://careerexplorer.com", "/api/v1/login")
            == "https://careerexplorer.com/api/v1/login"
        )

    def test_url_join_https_no_leading_slash_on_path(self):
        assert (
            ServiceRequestFactory.urljoin("https://careerexplorer.com", "api/v1/login")
            == "https://careerexplorer.com/api/v1/login"
        )

    def test_url_join_https_leading_slash_on_both(self):
        assert (
            ServiceRequestFactory.urljoin(
                "https://careerexplorer.com/", "/api/v1/login"
            )
            == "https://careerexplorer.com/api/v1/login"
        )

    def test_url_join_local_base_url(self):
        assert (
            ServiceRequestFactory.urljoin(
                "https://socket-service.sokanu-dev1.local/", "/test"
            )
            == "https://socket-service.sokanu-dev1.local/test"
        )
