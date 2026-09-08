## Verdict

**CWE-862: Missing Authorization** — CONFIRMED

The `ApiKeyViewSet` class exposes all ModelViewSet operations (list, retrieve, create, destroy) without defining `permission_classes`, allowing unauthorized access to internal API keys.

## Source

```python
from rest_framework import viewsets

from .models import ApiKey
from .serializers import ApiKeySerializer


# SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
```

## Fix

### File: views.py

```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import ApiKey
from .serializers import ApiKeySerializer


# SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    permission_classes = [IsAuthenticated]
    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
```

## Explanation

The vulnerability occurs because `ApiKeyViewSet` does not explicitly define `permission_classes`. Without this, Django REST Framework either uses the global default setting or allows unrestricted access, enabling unauthorized users to view, modify, or delete API keys.

The fix adds `permission_classes = [IsAuthenticated]` to require that only authenticated users can access the viewset's operations. This is imported from `rest_framework.permissions`.

For internal API keys used in service-to-service integrations, authentication is the baseline protection. More restrictive permission classes like `IsAdminUser` or custom role-based permissions could be substituted depending on the application's authorization model.
