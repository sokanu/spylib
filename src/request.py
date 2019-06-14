from __future__ import absolute_import
from requests import get, delete, post, patch, put
from .exceptions import MethodException, LoginException, RefreshException
from jwt import decode, DecodeError
from jwt.exceptions import ExpiredSignatureError
from six.moves.urllib.parse import urljoin


class Request(object):
    """
    Contains methods for cross service requests.
    """

    def __init__(
        self,
        base_url,
        access_token=None,
        secret=None,
        algorithm=None,
        refresh_token=None,
    ):
        try:
            self.access_token = access_token
            self.refresh_token = refresh_token
            self.base_url = base_url
            self.secret = secret
            self.algorithm = algorithm

            if self.access_token:
                decode(access_token, secret, algorithms=[algorithm])
        except ExpiredSignatureError:
            self.access_token = self.refresh(refresh_token)
        except (DecodeError, KeyError, Exception) as e:
            raise e

    def make_service_request(
        self, path=None, method="GET", payload=None, timeout=2, retry=True, **kwargs
    ):
        headers = kwargs.get("headers", {})
        if self.access_token:
            headers.update({"Authorization": "Bearer %s" % self.access_token})
        url = urljoin(self.base_url, path)

        if method == "GET":
            resp = get(url, params=payload, headers=headers, timeout=timeout, **kwargs)
        elif method == "DELETE":
            resp = delete(url, headers=headers, timeout=timeout, **kwargs)
        elif method == "POST":
            resp = post(url, json=payload, headers=headers, timeout=timeout, **kwargs)
        elif method == "PATCH":
            resp = patch(url, json=payload, headers=headers, timeout=timeout, **kwargs)
        elif method == "PUT":
            resp = put(url, json=payload, headers=headers, timeout=timeout, **kwargs)
        else:
            raise MethodException

        UNKNOWN_SERVER_ERROR = 500

        if retry and resp.status_code >= UNKNOWN_SERVER_ERROR:
            return self.make_service_request(
                path=path, method=method, payload=payload, timeout=timeout, retry=False
            )
        elif resp.status_code == 401:
            try:
                decode(self.access_token, self.secret, algorithms=[self.algorithm])
            except ExpiredSignatureError:
                if not self.refresh_token:
                    raise ExpiredSignatureError
                self.access_token = self.refresh(self.refresh_token)
                return self.make_service_request(
                    path=path,
                    method=method,
                    payload=payload,
                    timeout=timeout,
                    retry=False,
                )
        return resp

    # TODO: These should be hardcoded to auth sub-domain.

    def refresh(self, refresh_token):
        if not refresh_token:
            raise RefreshException
        cookies = {"refresh_token": refresh_token}
        resp = self.make_service_request(
            path="/api/v1/tokens", method="POST", payload={}, timeout=2, cookies=cookies
        )
        if resp.status_code != 201:
            raise RefreshException
        access_token = resp.json().get("access_token")
        if not access_token:
            raise RefreshException
        return access_token

    def login(self, uuid, api_key):
        """
        Login a user on auth, returns access_token and refresh_token.
        """
        resp = self.make_service_request(
            "api/v1/login", method="POST", payload={"api_key": api_key, "uuid": uuid}
        )
        if resp.status_code != 200:
            raise LoginException("Auth service login failed")
        access_token = resp.json().get("access_token")
        refresh_token = resp.cookies["refresh_token"]
        if access_token is None or refresh_token is None:
            raise LoginException
        return {"access_token": access_token, "refresh_token": refresh_token}
