"""
Contains methods for cross service requests.
"""
from __future__ import absolute_import
from six.moves.urllib.parse import urljoin
from requests import get, delete, post, patch, put
from exceptions import MethodException, LoginException


class Request(object):
    def __init__(self, base_url):
        self.base_url = base_url

    def make_service_request(
        self,
        token,
        path=None,
        method="GET",
        payload=None,
        retry=True,
        timeout=2,
        auth_credentials=None,
        retry_count=1,
    ):
        # TODO: Need to determine best way of handling MOCK for local.
        headers = {"Authorization": "Bearer %s" % token}
        url = urljoin(self.base_url, path)
        if method not in ["GET", "DELETE", "POST", "PATCH", "PUT"]:
            raise Exception

        if method == "GET":
            resp = get(url, params=payload, headers=headers, timeout=timeout)
        elif method == "DELETE":
            resp = delete(url, headers=headers, timeout=timeout)
        elif method == "POST":
            resp = post(url, json=payload, headers=headers, timeout=timeout)
        elif method == "PATCH":
            resp = patch(url, json=payload, headers=headers, timeout=timeout)
        elif method == "PUT":
            resp = put(url, json=payload, headers=headers, timeout=timeout)
        else:
            raise MethodException("Invalid method provided to HTTP request")

        if retry_count > 0 and resp.status_code < 200 and resp.status_code >= 300:
            self.make_service_request(
                token,
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                auth_credentials=auth_credentials,
                retry_count=retry_count - 1,
            )
        """
        # fetch new jwt if unauthorized
        if retry and resp.status_code == 401:
            cache.set("AUTH_JWT_TOKEN", token_method())
            self.make_service_request(
                base_url, path=path, method=method, payload=payload, retry=False
            )
        """
        return resp

    def get_auth_jwt(self, uuid, api_key):
        """
        makes a request to auth /login endpoint, and returns the jwt that is obtained
        """
        url = urljoin(self.base_url, "api/v1/login")
        resp = post(url, json={"api_key": api_key, "uuid": uuid})
        if resp.status_code != 200:
            raise LoginException("Auth service login failed")
        return resp.json().get("access_token")

    """
    @staticmethod
    def get_mock_jwt():
        return os.environ.get("AUTH_JWT_TOKEN_STUB")

    @staticmethod
    def get_token_method():
        if os.environ.get("AUTH_JWT_TOKEN_STUB") and settings.DEBUG:
            return BabelFish.get_mock_jwt
        return BabelFish.get_auth_jwt
    """


# def _get_jwt():
