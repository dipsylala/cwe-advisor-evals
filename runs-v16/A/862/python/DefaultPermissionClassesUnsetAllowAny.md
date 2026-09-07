## Verdict
Confirmed. The `ApiKeyViewSet` has no explicit `permission_classes` attribute and the Django settings define no `DEFAULT_PERMISSION_CLASSES`, causing Django REST Framework to fall back to `AllowAny`. This permits unauthenticated access to list, retrieve, create, and delete sensitive API keys. CWE-862: Missing Authorization.

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
```python
from rest_framework import viewsets, permissions

from .models import ApiKey
from .serializers import ApiKeySerializer


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Allow access only to the owner of an API key."""

    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user


class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def get_queryset(self):
        """Restrict queryset to the authenticated user's API keys."""
        return ApiKey.objects.filter(owner=self.request.user)
```

## Explanation
The fix adds two layers of authorization:

1. **`permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]`** enforces that only authenticated users can access the viewset, and only the owner of an API key can view or modify it.

2. **`IsOwnerOrReadOnly` custom permission class** checks that `obj.owner == request.user` before allowing object-level access to retrieve, update, or delete endpoints.

3. **`get_queryset()` override** restricts the list endpoint to return only API keys owned by the authenticated user, preventing information disclosure of other users' keys.

These changes ensure that unauthenticated users cannot enumerate or modify any API keys, and authenticated users can only access their own keys—closing the authorization gap at line 8.
