## Verdict

Exploitable. `ApiKeyViewSet` sets neither `permission_classes` nor a scoped `get_queryset()`, and `settings.py` sets no `DEFAULT_PERMISSION_CLASSES`, so DRF falls back to its built-in default of `AllowAny`. Any caller - authenticated or not - can list, retrieve, and destroy every `ApiKey` row for every user via the router registered in `urls.py`, and any authenticated caller can create an `ApiKey` for an arbitrary `owner` since the serializer exposes `owner` as writable with no per-object check on create.

## Source

The HTTP request reaching `ApiKeyViewSet` through the `DefaultRouter` registration in `urls.py` (`router.register("api-keys", ApiKeyViewSet, basename="apikey")`) is the source - an unauthenticated or unprivileged caller controls the request entirely, including any `owner` value supplied in a create payload.

## Fix

### File: views.py

```python
from rest_framework import permissions, viewsets

from .models import ApiKey
from .serializers import ApiKeySerializer


class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    serializer_class = ApiKeySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ApiKey.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
```

## Explanation

`permission_classes = [permissions.IsAuthenticated]` closes the missing-authentication gap left by the unset `DEFAULT_PERMISSION_CLASSES` (which defaults to `AllowAny`), so an unauthenticated caller is rejected before the view runs at all. That alone is not sufficient: DRF's generic list/detail actions skip any per-instance permission check and rely entirely on the queryset to decide which rows exist for a given caller, so `get_queryset()` now scopes to `ApiKey.objects.filter(owner=self.request.user)` instead of the original `ApiKey.objects.all()`. Because `retrieve()` and the router's destroy action both call `self.get_object()`, which looks the row up inside this same scoped queryset, a request for another user's key now 404s exactly as a nonexistent id would, rather than either succeeding (the original bug) or 403ing and confirming the row exists. Finally, `perform_create()` forces `owner=self.request.user` on save, which DRF applies after the serializer's own validated data, so a client-supplied `owner` field in the POST body can no longer plant or take over a key for a different user - object-level authorization is otherwise never invoked on create.

## Behaviour changes

- Unauthenticated requests to any action on this endpoint now receive `401 Unauthorized` (via `TokenAuthentication`'s challenge header) instead of `200`/successful data - this is the intended effect of closing the missing-authorization finding, not a side effect.
- `list` now returns only the requesting user's own `ApiKey` rows instead of every user's rows - required to prevent authenticated non-owners from reading other users' keys, since DRF does not apply an object-level check on list actions.
- `retrieve` and `destroy` on another user's key now return `404 Not Found` instead of `200`/succeeding - this follows the loaded guidance's rule that an ownership check on a guessable identifier should scope the lookup and return the same 404 used for a nonexistent row, rather than a 403 that would confirm the row exists.
- `create` now ignores any `owner` value supplied in the request body and always assigns the authenticated caller as owner, instead of honoring a client-supplied `owner` - required because DRF never runs an object-level permission check on create, so the serializer's writable `owner` field was the only thing standing between an authenticated caller and creating a key attributed to an arbitrary user.
- The `queryset = ApiKey.objects.all()` class attribute was removed in favor of the `get_queryset()` override above; it is unused once `get_queryset()` is defined; this is a mechanical consequence of the ownership-scoping fix, not a separate behavior change.
- No change to `models.py`, `serializers.py`, `settings.py`, or `urls.py` - the serializer's `owner` field is left writable (harmless now that `perform_create()` always overrides it with the authenticated caller), and roles/permissions for the endpoint are otherwise unchanged from what the code already expressed (any authenticated user may manage their own keys).

**Verification**: `python -m py_compile` on the fixed `views.py` in isolation succeeded with no errors. `permissions.IsAuthenticated`, `viewsets.ModelViewSet`, `get_queryset()`, and `perform_create()` are standard `rest_framework` APIs already implied by the existing `ModelViewSet` base class; `self.request.user` is the standard DRF request attribute populated by the authentication classes already configured in `settings.py` (`SessionAuthentication`, `TokenAuthentication`). No new third-party dependency was introduced.

**Assumption**: `ApiKey.owner` (a `ForeignKey` to `AUTH_USER_MODEL`) is the correct ownership field to scope by, since it is the only user-relationship field on the model and matches the "service-to-service integrations" ownership implied by the docstring; no comparable sibling viewset was present in this case to confirm the pattern against, so this is the best-supported interpretation rather than a confirmed match to an existing convention.
