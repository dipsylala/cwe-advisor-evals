## Verdict

Exploitable. The `ModelViewSet` declares no `permission_classes` attribute, causing Django REST Framework to default to `AllowAny`, granting unrestricted access to all CRUD operations on API keys regardless of user authentication or authorization status.

## Source

HTTP requests to the viewset's endpoints (list, retrieve, create, destroy) from any client, including unauthenticated users and users lacking administrative privileges.

## Fix

### File: views.py

```python
from rest_framework import viewsets, permissions

from .models import ApiKey
from .serializers import ApiKeySerializer


class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    permission_classes = [permissions.IsAdminUser]
    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
```

## Explanation

The original viewset lacks an explicit `permission_classes` attribute. In Django REST Framework, when a viewset or APIView does not declare `permission_classes`, the framework defaults to `AllowAny` (or the global `DEFAULT_PERMISSION_CLASSES` setting if configured, but absence of that setting is also `AllowAny`), granting unrestricted access. This is a dangerous default for sensitive operations like managing API keys, which should only be accessible to authorized administrators.

The fix adds `permission_classes = [permissions.IsAdminUser]`, which enforces that only users with administrative privileges can list, retrieve, create, or destroy API keys. DRF checks this permission before executing any viewset action, returning a 403 Forbidden response to non-admin users. The import of `permissions` from `rest_framework` is added to make `IsAdminUser` available.

## Behaviour changes

The only change is the addition of the `permission_classes` attribute. This enforces authorization where none existed: non-admin users now receive a 403 Forbidden response instead of being granted access to API key operations. The viewset's core CRUD functionality is unchanged; only access control is added. The queryset, serializer, and docstring are unaffected.
