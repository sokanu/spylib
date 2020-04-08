"""Auth Client file for Spylib."""

from __future__ import absolute_import
from .exceptions import APIException
from .request import ServiceRequestFactory
from .settings import AUTH_BASE_URL
from typing import Union


class AuthClient(ServiceRequestFactory):
    """AuthClient used for intra service communication."""

    def __init__(self, *args, **kwargs):
        """Auth Client Init."""
        super(AuthClient, self).__init__(*args, **kwargs)

    def create_entity(
        self,
        email: Union[str, None] = None,
        description: Union[str, None] = None,
        password: Union[str, None] = None,
        permissions: list = [],
        permission_sets: list = [],
    ) -> Union[dict, APIException]:
        """
        Create a new user entity on auth.

        Optionally append a password, or api_key to the entity.

        Args:
            email(str): An email for the entity.
            description(str): A description of the entity.
            password(str): Password of the entity.
            permissions(list): List of permissions.
            permission_sets(list): List of permission sets.

        """
        payload = {
            "permissions": permissions,
            "permission_sets": permission_sets,
            "password": password,
            "email": email,
            "description": description,
        }
        resp = self.post(
            AUTH_BASE_URL, "/api/v1/entities", payload=payload, timeout=1.0
        )
        if resp.status_code == 201:
            return resp.json()
        raise APIException(
            message="Create Auth Entity failed with code %d" % resp.status_code
        )

    def create_entity_api_key(self, entity_uuid: str, api_key_is_active: bool = True):
        """
        Create a new entity api key on auth.

        Args:
            entity_uuid(str): Entity uuid to associate the api key with.
            api_key_is_active(bool): Whether the api key is active, or inactive.

        """
        payload = {"entity": str(entity_uuid), "is_active": api_key_is_active}
        resp = self.post(
            AUTH_BASE_URL, "/api/v1/entity-api-keys", payload=payload, timeout=1.0
        )
        if resp.status_code == 201:
            return resp.json()
        raise APIException(
            message="create api key call failed with bad response status code of %d"
            % resp.status_code
        )

    def create_auth_perm(self, owner_uuid, permission_name, description=None):
        """
        Create a permission on auth called `permission_name` that's owned by the `owner_uuid` and with description if provided.

        Returns the resulting JSON from the request.

        Args:
            owner_uuid(str): UUID of the owner of the permission.
            permission_name(str): Name of the permission.
            description(str): Description of the permission.

        """
        payload = {
            "owner": str(owner_uuid),
            "name": permission_name,
            "description": description,
        }
        resp = self.post(
            AUTH_BASE_URL, "/api/v1/permissions", payload=payload, timeout=1.0
        )
        if resp.status_code == 201:
            return resp.json()

        raise APIException(
            message="create auth perm api call  returned bad resp code %d"
            % resp.status_code
        )

    def associate_entity_with_permission(
        self, entity_uuid, permission_name, permission_owner_uuid
    ):
        """
        Given an entity uuid, a permission name and that permissions owner - associates the entity with that permission.

        Returns the resulting JSON from the request.

        Args:
            entity_uuid(str): UUID of the entity.
            permission_name(str): Name of the permission.
            permission_owner_uuid(str): UUID belonging to the owner of the permission.

        """
        payload = {
            "entity": str(entity_uuid),
            "permissions": [{"owner": permission_owner_uuid, "name": permission_name}],
        }
        resp = self.post(
            AUTH_BASE_URL, "/api/v1/entity-permissions", payload=payload, timeout=1.0
        )
        if resp.status_code != 201:
            raise APIException(
                message="grant_entity_auth_perm API call returned a bad response code %d"
                % resp.status_code
            )
        try:
            json = resp.json()
            # Fetch new tokens since permissions changed.
            self.fetch_new_tokens()
        except ValueError:
            raise APIException(
                message="grant_entity_auth_perm API call failed to decode a JSON response"
            )
        else:
            return json

    def deassociate_entity_with_permission(
        self, entity_uuid, permission_name, permission_owner_uuid
    ):
        """
        Given an entity uuid, a permission name, and that permissions owner - deassociates the given entity uuid with that permission.

        The expected side effect from this function, upon success, is that the entity no longer has access to the provided permission.

        On sucess, is a void function

        On failure, raises an APIException.

        Following the deletion, the client's tokens are fetched to make the access token reflect changes on auth.

        Args:
            entity_uuid(str): UUID of the entity.
            permission_name(str): Name of the permission.
            permission_owner_uuid(str): UUID belonging to the owner of the permission.

        """
        payload = {
            "entity": str(entity_uuid),
            "permissions": [{"owner": permission_owner_uuid, "name": permission_name}],
        }
        resp = self.delete(
            AUTH_BASE_URL, "/api/v1/entity-permissions", timeout=1.0, json=payload
        )
        if resp.status_code != 200:
            raise APIException(
                message="deassociate_entity_with_permission API call returned a bad response code %d"
                % resp.status_code
            )
        self.fetch_new_tokens()
