from __future__ import absolute_import
from six.moves.urllib.parse import urljoin
from requests import get, delete, post, patch, put
from exceptions import MethodException, LoginException, RefreshException
from jwt import decode, DecodeError, ExpiredSignatureError


class Request(object):
    """
    Contains methods for cross service requests.
    """

    def __init__(self, base_url, access_token, secret, algorithm, refresh_token=None):
        try:
            decode(access_token, secret=secret, algorithms=[algorithm])
            self.access_token = access_token
        except ExpiredSignatureError:
            self.access_token = Request.refresh(base_url, refresh_token)
        except (DecodeError, KeyError, Exception) as e:
            raise e
        else:
            self.refresh_token = refresh_token
            self.base_url = base_url

    def make_service_request(
        self, path=None, method="GET", payload=None, timeout=2, retry_count=1
    ):
        headers = {"Authorization": "Bearer %s" % self.access_token}
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

        UNKNOWN_SERVER_ERROR = 500

        if retry_count > 0 and resp.status_code >= UNKNOWN_SERVER_ERROR:
            self.make_service_request(
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                retry_count=retry_count - 1,
            )
        elif resp.status_code == 401:
            try:
                decode(self.access_token, self.secret, algorithms=[self.algorithm])
            except ExpiredSignatureError:
                if not self.refresh_token:
                    raise ExpiredSignatureError
                self.access_token = Request.refresh(self.refresh_token)
                self.make_service_request(
                    path=path,
                    method=method,
                    payload=payload,
                    timeout=timeout,
                    retry_count=retry_count - 1,
                )
        return resp

    @staticmethod
    def refresh(base_url, refresh_token):
        if not refresh_token:
            raise RefreshException
        url = urljoin(base_url, "api/v1/tokens")
        cookies = {"refresh_token": refresh_token}
        resp = post(url, cookies=cookies, timeout=2)
        if resp.status_code != 201:
            raise RefreshException
        return resp.json().get("access_token")

    @staticmethod
    def login(base_url, uuid, api_key):
        """
        Login a user on auth, the access_token and refresh_token on the object.
        """
        url = urljoin(base_url, "api/v1/login")
        resp = post(url, json={"api_key": api_key, "uuid": uuid})
        if resp.status_code != 200:
            raise LoginException("Auth service login failed")
        return {
            "access_token": resp.json().get("access_token"),
            "refresh_token": resp.cookies["refresh_token"],
        }
