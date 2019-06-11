"""
Contains methods for cross service requests.
"""
from __future__ import absolute_import
from six.moves.urllib.parse import urljoin
from requests import get, delete, post, patch, put
from exceptions import MethodException


def make_service_request(
    self,
    token,
    base_url,
    path=None,
    method="GET",
    payload=None,
    retry=True,
    timeout=2,
    auth_credentials=None,
    retry_count=1,
):
    headers = {"Authorization": "Bearer %s" % token}
    url = urljoin(base_url, path)
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
            base_url,
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


# def _get_jwt():
