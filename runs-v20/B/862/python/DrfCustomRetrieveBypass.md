## Verdict

exploitable

- cwe_id: CWE-862 (Missing Authorization)
- location: `views.py`, line 21 (sink), within `InvoiceViewSet.retrieve()`
- confidence: high

## Source

The tainted input is the `pk` path parameter from the incoming HTTP request, routed by DRF into `InvoiceViewSet.retrieve(self, request, pk=None)`. Any authenticated user (the class only requires `IsAuthenticated` plus the object-level `IsInvoiceOwner` permission) can supply an arbitrary invoice id here.

## Fix

### File: views.py

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .models import Invoice
from .permissions import IsInvoiceOwner


class InvoiceViewSet(ModelViewSet):
    serializer_class = None
    permission_classes = [IsAuthenticated, IsInvoiceOwner]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Invoice.objects.all()
        return Invoice.objects.filter(owner_id=self.request.user.id)

    def retrieve(self, request, pk=None):
        invoice = self.get_object()
        return Response({
            "id": invoice.id,
            "owner_id": invoice.owner_id,
            "total_cents": invoice.total_cents
        })
```

## Explanation

The custom `retrieve()` looked the invoice up directly with `get_object_or_404(Invoice, pk=pk)`, which queries the unscoped model manager and never calls DRF's `get_object()`. That skipped both halves of the authorization the class declares: the ownership-scoped `get_queryset()` (which filters to the caller's own rows unless they are staff) and `IsInvoiceOwner.has_object_permission()` (which only runs when something calls `check_object_permissions()`). The result was that any authenticated user could read any invoice by id regardless of ownership.

The fix replaces the manual lookup with `self.get_object()`, the same method DRF's built-in `retrieve()` mixin uses. It resolves the object through `self.get_queryset()` - so a non-staff caller can only ever match rows they own - and then calls `self.check_object_permissions()` internally, running `IsInvoiceOwner.has_object_permission()` as a second layer for anyone who does reach a row in that queryset. The custom method still hand-serializes the response instead of calling `get_serializer()`, since `serializer_class` is left unset here; that formatting was preserved as-is and is unrelated to the authorization gap. Because the fix routes through the same scoped queryset used elsewhere in the class rather than adding a bare `check_object_permissions()` call after the unscoped fetch, a non-owned invoice id still raises the queryset's own `Http404` (not found in the scoped result set) instead of a `PermissionDenied` (403) that would confirm the record exists - preserving the existing indistinguishable "missing vs. not yours" behavior for ordinary users, while staff continue to match every row via the widened `get_queryset()` branch.

## Behaviour changes

- Replaced `get_object_or_404(Invoice, pk=pk)` (unscoped manager query) with `self.get_object()` (scoped by `get_queryset()`, then object-permission-checked). Reason: closes the missing-authorization gap by routing through the same ownership scoping and permission check every other action on this viewset already relies on.
- Removed the now-unused `from django.shortcuts import get_object_or_404` import. Reason: the import's only call site was removed by the fix above; nothing else in the file used it.
- No change to the response shape, status codes returned to legitimate callers, staff behavior, or the "not found" response for a non-owned or nonexistent id - both still resolve to the same 404 as before, since the fix scopes the lookup rather than adding a separate permission check after an unscoped one.
- verification: `python -m py_compile` on the fixed file in isolation - exit 0, no syntax errors. `rest_framework` is not installed in this environment, so the import chain itself was not executed; `self.get_object()` was checked by hand against DRF's `GenericAPIView` implementation (used via `ModelViewSet`'s MRO), which calls `self.filter_queryset(self.get_queryset())`, looks up by the URL's `pk` kwarg, and calls `self.check_object_permissions()` before returning - no new symbols were introduced, since `get_object()` is inherited and `Invoice`/`IsInvoiceOwner`/`Response` were already imported and used in the original file.
- assumptions: none required - the trace matches the DRF-documented behavior of `get_object()` cited in the loaded language guidance (`cwe/862/python/INDEX.md`) with no ambiguity to resolve.
