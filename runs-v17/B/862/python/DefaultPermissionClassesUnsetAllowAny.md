## Verdict

Exploitable. The `ApiKeyViewSet` lacks `permission_classes`, defaulting to `AllowAny` under Django REST Framework. This allows any user (authenticated or unauthenticated) to list, retrieve, create, or delete API keys via the default CRUD endpoints provided by `ModelViewSet`.

## Source

Django REST Framework's default permission handling. When `permission_classes` is not explicitly set on a `ViewSet`, it uses `DEFAULT_PERMISSION_CLASSES` from settings. If that is unset, it defaults to `AllowAny`, permitting unrestricted access.

## Fix

### File: views.py

```python
from rest_framework import viewsets
from rest_framework.permissions import IsAdminUser

from .models import ApiKey
from .serializers import ApiKeySerializer


class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes = [IsAdminUser]
```

## Explanation

The fix adds `permission_classes = [IsAdminUser]` to explicitly require admin status for all operations on the `ApiKeyViewSet`. This replaces the implicit `AllowAny` default with an explicit authorization check that runs before any action (list, retrieve, create, update, delete) executes. `IsAdminUser` is a built-in DRF permission class that checks `request.user.is_staff` before allowing access. Any unauthenticated or non-admin user will now receive a 403 Forbidden response instead of access to sensitive API keys. The import of `IsAdminUser` from `rest_framework.permissions` provides the permission class; it is part of the standard Django REST Framework library already required by the codebase.

## Behaviour changes

- Added import: `from rest_framework.permissions import IsAdminUser` — imported from the DRF package included in the project dependencies.
- Added attribute: `permission_classes = [IsAdminUser]` — restricts all ViewSet actions (list, retrieve, create, update, destroy) to users with admin status; authenticated non-admin users and unauthenticated users now receive 403 responses where they previously received 200.
- Response contract: All endpoint responses now include a 403 for unauthorized access; this is the intended hardening and differs from the previous behavior only in that unauthorized access is now properly denied.
