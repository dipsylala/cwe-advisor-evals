## Verdict

**Confirmed.** The `ApiKeyViewSet` lacks an explicit `permission_classes` attribute. In Django REST Framework, this defaults to `AllowAny`, permitting any unauthenticated or authenticated user to list, retrieve, create, and destroy API keys. The finding is exploitable as reported.

## Source

**File:** `evals/cases/862/python/DefaultPermissionClassesUnsetAllowAny/views.py`  
**Line:** 8  
**Sink:** `class ApiKeyViewSet(viewsets.ModelViewSet):` — the ViewSet exposes all CRUD operations via the inherited ModelViewSet without authorization checks.

**Data flow:**  
The `ApiKeyViewSet` is routed as a DRF viewset, making its actions (list, retrieve, create, destroy) available as HTTP endpoints. Without `permission_classes`, the router applies the `DEFAULT_PERMISSION_CLASSES` setting from DRF's configuration. When that setting is unset (the default), DRF falls back to `AllowAny`, which grants access to all callers regardless of authentication or authorization status.

## Fix

Add the `IsAdminUser` permission class to restrict access to authenticated administrative users:

```python
from rest_framework import viewsets
from rest_framework.permissions import IsAdminUser

from .models import ApiKey
from .serializers import ApiKeySerializer


# SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    permission_classes = [IsAdminUser]
    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
```

## Explanation

The fix adds `permission_classes = [IsAdminUser]` to the `ApiKeyViewSet`. This explicit setting overrides the default `AllowAny` and enforces that only authenticated users with `is_staff=True` (or equivalent admin status) can access any operation on this viewset. `IsAdminUser` is a built-in Django REST Framework permission class from `rest_framework.permissions`.

The import statement adds the required dependency. Setting `permission_classes` at the viewset level ensures the check runs before any action (list, retrieve, create, destroy) executes. This aligns with the guidance to centralize authorization through DRF's permission framework rather than adding ad-hoc checks.

## Behaviour changes

- **Before:** Any HTTP request to list, retrieve, create, or destroy API keys succeeds, returning data or accepting mutations without authentication or authorization.
- **After:** Requests without a valid session cookie/token receive a 403 Forbidden response. Requests from authenticated non-admin users receive a 403 Forbidden response. Only authenticated admin users can perform operations on this viewset.
- **Testing:** Call each endpoint (GET /api-keys/, POST /api-keys/, GET /api-keys/{id}/, DELETE /api-keys/{id}/) as an unauthenticated user and confirm the response is 403. Repeat as an authenticated non-admin user and confirm 403. Repeat as an admin user and confirm success (200 or 201/204 as appropriate).
