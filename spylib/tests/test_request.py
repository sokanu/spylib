from __future__ import absolute_import
from ..request import ServiceRequestFactory, Observer
from ..exceptions import AuthCredentialException
from ..exceptions import ServiceUnavailable, PermissionDenied
import uuid
import datetime
import json
import jwt
import unittest
import responses
import os

# sys.setrecursionlimit(60)

JWT_SECRET = "1234"
JWT_ALGORITHM = "HS256"


def generate_access_token(expiry):
    return jwt.encode({"exp": expiry}, JWT_SECRET, algorithm=JWT_ALGORITHM).decode(
        "utf-8"
    )


def generate_good_access_token():
    return generate_access_token(datetime.datetime.now() + datetime.timedelta(30))


def generate_expired_access_token():
    return generate_access_token(datetime.datetime.now() - datetime.timedelta(30))


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
        access_token = generate_good_access_token()
        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        assert srf.access_token == access_token
        assert srf.secret
        assert srf.refresh_token is None

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
        access_token = generate_good_access_token()
        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            algorithm=JWT_ALGORITHM,
            secret=JWT_SECRET,
            refresh_token="billy",
        )
        assert srf.access_token == access_token
        assert srf.secret
        assert srf.refresh_token == "billy"

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
            - throws a AuthCredentialException
        """
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/tokens", status=500
        )
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/login", status=500
        )
        with self.assertRaises(ServiceUnavailable):
            ServiceRequestFactory(
                uuid=str(uuid.uuid4()),
                api_key="1234",
                access_token=generate_expired_access_token(),
                algorithm=JWT_ALGORITHM,
                secret=JWT_SECRET,
            )

    @responses.activate
    def test_refresh_token_gets_new_access_token_success(self):
        """
        Given:
            - an expired access token.
            - a mocked URL returning a 201 from the refresh token endpoint.
            - a refresh token.
        When:
            - Refresh token endpoint succeeds.
        Outcome:
            - the request object has the response from the mocked url.
        """
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            body=json.dumps({"access_token": "1234"}),
        )
        res = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_expired_access_token(),
            algorithm=JWT_ALGORITHM,
            secret=JWT_SECRET,
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
            - AuthCredentialException is raised.
        """
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/login", status=401
        )
        with self.assertRaises(AuthCredentialException):
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
            - AuthCredentialException raised.
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
        srf = ServiceRequestFactory(uuid="fake", api_key="fake")
        assert srf.access_token == "5678"
        assert srf.refresh_token == "1234"

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

        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_good_access_token(),
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        with self.assertRaises(ServiceUnavailable):
            srf.make_service_request(
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
            - a good access token
            - retry option is configured to retry once.
            - first request return a 500.
        When:
            - a make service request is executed
        Outcome:
            - expect the service to be called twice.
        """
        responses.add(responses.GET, "https://my-service/api/v1/test", status=500)
        responses.add(responses.GET, "https://my-service/api/v1/test", status=200)

        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_good_access_token(),
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            retry_count=1,
        )

        resp = srf.make_service_request(
            "https://my-service", path="/api/v1/test", method="GET", retry_count=1
        )
        assert resp.status_code == 200
        assert responses.calls.__len__() == 2

    @responses.activate
    def test_make_service_request_no_retry_succeeds(self):
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
        access_token = generate_good_access_token()
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        with self.assertRaises(ServiceUnavailable):
            resp.make_service_request(
                "https://auth.localhost:8000",
                path="/api/v1/test",
                method="POST",
                retry_count=0,
                payload={},
            )
        assert responses.calls.__len__() == 1

    @responses.activate
    def test_make_service_request_succeeds_with_expired_token_and_refresh_token_after_single_auth_failure(
        self
    ):
        """
        Given:
            - an expired access token.
            - good refresh token.
            - token refresh fails once.
            - token refresh succeeds second pass.
        When:
            - a make service request is executed
        Outcome:
            - a 200 is returned.
        """
        # order here matters. matching urls will be hit in the order declared.
        responses.add(
            responses.GET, "https://some-service:8000/api/v1/test", status=200, json={}
        )
        responses.add(
            responses.POST, "https://auth.localhost:8000/api/v1/tokens", status=500
        )
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            json={"access_token": "1234"},
        )

        access_token = generate_expired_access_token()

        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=access_token,
            refresh_token="5678",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        resp = srf.make_service_request(
            "https://some-service:8000",
            path="/api/v1/test",
            method="GET",
            retry_count=0,
            payload={},
        )

        assert resp.status_code == 200
        assert responses.calls.__len__() == 3

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
            - new tokens are fetched
            - the response from the test server is retrieved.
        """
        responses.add(
            responses.GET, "https://my-service/api/v1/test", status=200, json={}
        )
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            json={"access_token": "1234"},
        )

        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_expired_access_token(),
            refresh_token="1a2a3a",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        resp = srf.make_service_request(
            "https://my-service", path="/api/v1/test", method="GET"
        )
        assert resp.status_code == 200

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
        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_good_access_token(),
            refresh_token="1a2a3a",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        resp = srf.make_service_request(
            "https://auth.localhost:8000",
            path="/api/v1/test",
            method="DELETE",
            retry_count=0,
        )
        assert resp.status_code == 200

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
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_good_access_token(),
            refresh_token="1a2a3a",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
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
        resp = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_good_access_token(),
            refresh_token="1a2a3a",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
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
        access_token = generate_good_access_token()
        req_obj = ServiceRequestFactory(
            "1234",
            "4321",
            access_token=access_token,
            refresh_token="321",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
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

    @responses.activate
    def test_observable_triggers_observer_notify(self):
        """
        Given a login that gives you a new access/refresh token, and a implemented observer pattern.
        Expect that the observer is notified that the access and refresh token were changed.
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

        class AnObserver(Observer):
            access_token_modify = False
            refresh_token_modify = False

            def __init__(self):
                super().__init__()

            def notify(self, observable, *args, **kwargs):
                if str(observable.refresh_token) == str(1234):
                    self.refresh_token_modify = True
                if str(observable.access_token) == str(5678):
                    self.access_token_modify = True

        observer_instance = AnObserver()

        # Instantiation causes tokens to be fetched - afterwards tokens should be set
        ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            observer_lst=[observer_instance],
        )

        assert observer_instance.access_token_modify
        assert observer_instance.refresh_token_modify

    @responses.activate
    def test_make_service_request_good_token_service_rejects_403(self):
        """
        Given:
            - a good access token.
            - 403 by service.
        When:
            - a make service request is executed
        Outcome:
            - NotAuthenticated is raised.
        """
        # Mock requests to my-service
        responses.add(responses.GET, "https://my-service/api/v1/test", status=403)

        # Mock requests to auth for when the automatic retry happens
        responses.add(
            responses.POST,
            "https://auth.localhost:8000/api/v1/tokens",
            status=201,
            json={"access_token": "1234"},
        )

        srf = ServiceRequestFactory(
            uuid=str(uuid.uuid4()),
            api_key="1234",
            access_token=generate_good_access_token(),
            refresh_token="1a2a3a",
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        with self.assertRaises(PermissionDenied):
            srf.make_service_request(
                "https://my-service", path="api/v1/test", method="GET", payload={}
            )
        assert responses.calls.__len__() == 3
