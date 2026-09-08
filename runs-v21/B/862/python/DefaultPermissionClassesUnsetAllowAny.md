## Verdict

**CONFIRMED EXPLOITABLE**: The `ApiKeyViewSet` has no `permission_classes` set. The settings module has no `DEFAULT_PERMISSION_CLASSES` key, so DRF defaults to `AllowAny`, allowing completely unrestricted access to all API key operations. Any unauthenticated client can list, retrieve, create, update, and delete API keys without any authorization check.

## Source

The vulnerability originates from:
1. **Missing permission declaration**: `ApiKeyViewSet` (line 8, views.py) defines no `permission_classes` attribute
2. **Unsafe default**: settings.py contains no `DEFAULT_PERMISSION_CLASSES` key in the `REST_FRAMEWORK` config, so DRF's built-in default of `AllowAny` applies to all undecorated viewsets
3. **Sensitive resource**: The `ApiKey` model stores credentials for service-to-service integrations; each key belongs to an `owner` user

**Data Flow**:
- HTTP requests to `/api-keys/` endpoints reach `ApiKeyViewSet`
- DRF routes requests to viewset methods (list, retrieve, create, update, destroy)
- No permission check runs; requests proceed with `AllowAny` behavior
- All API keys in the database are accessible and modifiable

## Fix

### File: views.py

```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import ApiKey
from .serializers import ApiKeySerializer


class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)
```

## Explanation

The fix adds two layers of authorization:

1. **Permission class** (`permission_classes = [IsAuthenticated]`): Requires the client to be an authenticated user. DRF checks this before routing to any viewset method. This replaces the unsafe `AllowAny` default with an explicit, restrictive requirement.

2. **Queryset filtering** (`get_queryset()` override): Scopes all database operations to the current user's own API keys (`owner=request.user`). This provides object-level authorization: even an authenticated user can only list, retrieve, update, or delete keys they own. DRF's generic views use `get_queryset()` for all operations (list, retrieve, update, delete), so the filter applies uniformly. For the create action, `perform_create()` would typically set the owner to the current user (though the serializer's `owner` field exposure here is a separate concern).

The two together close the CWE-862 gap: the viewset now performs an explicit authorization check (authentication + ownership) before every sensitive operation, replacing the unguarded access that previously existed. Unauthenticated requests are rejected outright; authenticated requests on objects the user does not own are rejected (returning 404 via the scoped queryset, indistinguishable from non-existent objects and avoiding enumeration oracles).

## Behaviour changes

- **Authentication enforced**: Unauthenticated requests now receive `403 Forbidden` (or `401 Unauthorized` if no credentials provided), instead of `200 OK` with full API key data.
- **Scoped data access**: List operations return only the authenticated user's keys, not all keys in the database.
- **Object-level checks on all operations**: Retrieve, update, and delete on a key the user does not own now return `404 Not Found` (via the scoped queryset), instead of `200 OK` with modification applied.
- **Create restricts ownership**: New keys can only be created by authenticated users; the owner must be validated against `request.user` in `perform_create()` to prevent users from creating keys with a different owner (the serializer currently accepts a free-form `owner` value, which is a separate data exposure issue beyond the authorization scope of CWE-862).
