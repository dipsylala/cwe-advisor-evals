## Verdict

Exploitable. The ViewSet lacks an explicit `permission_classes` attribute, which causes Django REST Framework to default to `AllowAny`, granting unrestricted access to all endpoints that manage sensitive API key data.

## Source

**File:** evals/cases/862/python/DefaultPermissionClassesUnsetAllowAny/views.py  
**Line:** 8  
**Vulnerable pattern:** `class ApiKeyViewSet(viewsets.ModelViewSet):` with no `permission_classes` attribute

The ViewSet inherits `list()`, `retrieve()`, `create()`, and `destroy()` methods from `ModelViewSet` without any permission check. When `permission_classes` is absent, DRF defaults to the global `DEFAULT_PERMISSION_CLASSES` setting; if that is also unset, the fallback is `AllowAny`.

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
from rest_framework.permissions import IsAdminUser

class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes = [IsAdminUser]
```

## Explanation

The fix adds an explicit `permission_classes` attribute set to `[IsAdminUser]`, which restricts all ViewSet endpoints to admin users only. This closes the Missing Authorization gap by enforcing that only privileged users can list, retrieve, create, or destroy API keys. The permission check runs before the ViewSet action executes. For production environments managing service credentials, `IsAdminUser` provides a safe-by-default stance; if a multi-tenant or user-scoped model is needed, add a custom permission class that implements `has_object_permission()` to check resource ownership as well.

## Behaviour changes

**Requests from non-admin users** — Previously returned 200 OK and the requested data or action succeeded. Now return 403 Forbidden. This is the intended protection.

**Requests from admin users** — Behaviour unchanged; operations succeed as before.

**Response structure** — DRF returns a standard error response body for 403 rather than the requested resource or operation result. This is standard DRF behavior and expected by API clients that handle authorization correctly.
