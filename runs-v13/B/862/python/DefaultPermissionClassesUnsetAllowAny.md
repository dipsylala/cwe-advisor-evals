## Verdict

Exploitable. The ViewSet does not define `permission_classes`, which causes DRF to default to `AllowAny` when `DEFAULT_PERMISSION_CLASSES` is unset in settings. This permits unauthenticated users to list, retrieve, create, and delete API keys.

## Source

Absence of the `permission_classes` attribute on the ViewSet class.

## Fix

**Vulnerable code:**

```python
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
```

**Fixed code:**

```python
from rest_framework import viewsets, permissions

from .models import ApiKey
from .serializers import ApiKeySerializer


class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes = [permissions.IsAdminUser]
```

## Explanation

The fix adds an explicit `permission_classes` attribute set to `[permissions.IsAdminUser]`, which restricts all ViewSet operations (list, retrieve, create, update, delete) to users with admin/staff status. This replaces the unsafe default `AllowAny` behaviour that would allow unauthenticated users to access and modify API keys. The import statement for `permissions` is added from `rest_framework`. If a more granular permission model is needed (e.g., allowing authenticated non-admin users with specific permissions), a custom `BasePermission` subclass implementing both `has_permission()` and `has_object_permission()` should be created and used instead.

## Behaviour changes

None. The original code's lack of an explicit `permission_classes` silently defaulted to `AllowAny` (an unintended permissive state); the fix replaces that with an intentional restrictive default. There is no change to the ViewSet's return values, queryset logic, or serializer behaviour—only the authorization gate is added. New requests will be denied with HTTP 403 if the user lacks admin status, replacing the previous unrestricted HTTP 200 responses.
