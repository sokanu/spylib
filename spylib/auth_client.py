from .exceptions import APIException
from .request import ServiceRequestFactory
from .settings import AUTH_BASE_URL


class AuthClient(ServiceRequestFactory):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def create_auth_perm(self, owner_uuid, permission_name, description=None):
        """
        Creates a permission on auth called `permission_name` that's owned by the `owner_uuid` and with description if provided,
        Returns the resulting JSON from the request.
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
        """
        payload = {
            "entity": entity_uuid,
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
        """
        payload = {
            "entity": entity_uuid,
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
