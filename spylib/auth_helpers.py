from __future__ import absolute_import
from .exceptions import APIException
from .settings import AUTH_BASE_URL
from six.moves.urllib.parse import urljoin
import requests


def create_auth_perm(access_token, service_uuid, permission_name, description):
    headers = {"Authorization": "Bearer %s" % access_token}

    payload = {
        "owner": service_uuid,
        "name": permission_name,
        "description": description,
    }

    resp = requests.post(
        urljoin(AUTH_BASE_URL, "api/v1/permissions"),
        headers=headers,
        data=payload,
        timeout=1.0,
    )

    if resp.status_code == 201:
        return resp.json()

    else:
        raise APIException(
            message="create_auth_perm API call returned a bad response code %d"
            % resp.status_code
        )


def grant_entity_auth_perm(access_token, service_uuid, permission_name, entity_uuid):
    headers = {"Authorization": "Bearer %s" % access_token}

    payload = {
        "entity": entity_uuid,
        "permissions": [{"owner": service_uuid, "name": permission_name}],
    }

    resp = requests.post(
        urljoin(AUTH_BASE_URL, "api/v1/entity-permissions"),
        headers=headers,
        data=payload,
        timeout=1.0,
    )

    if resp.status_code == 201:
        return resp.json()

    else:
        raise APIException(
            message="grant_entity_auth_perm API call returned a bad response code %d"
            % resp.status_code
        )
