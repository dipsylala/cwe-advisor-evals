## Verdict

The ViewSet lacks explicit permission classes, defaulting to allow any request (per DRF's default `permission_classes = []`). This permits unauthorized users to list, retrieve, create, and delete API keys.

## Source

```python
# Line 8: vulnerable class definition
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
```

The `permission_classes` attribute is absent, so DRF applies the default permission policy, which is typically `AllowAny` unless overridden at the settings level.

## Fix

### File: views.py

```python
from rest_framework import viewsets, permissions

from .models import ApiKey
from .serializers import ApiKeySerializer


# SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes = [permissions.IsAdminUser]
```

## Explanation

API keys are sensitive credentials used for service-to-service authentication. The ViewSet manages their full lifecycle (list, retrieve, create, destroy) and must restrict access to authorized users only.

Add `permission_classes = [permissions.IsAdminUser]` to restrict all endpoints to staff/admin users. This ensures only privileged administrators can view, create, or revoke API keys. Import `permissions` from `rest_framework` to access the built-in permission class.

For environments requiring different access patterns (e.g., users managing their own keys), implement a custom permission class that validates ownership or role-based access before proceeding.
