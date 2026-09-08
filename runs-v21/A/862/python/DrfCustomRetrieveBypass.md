## Verdict

**Confirmed.** The `retrieve()` method in `views.py` bypasses authorization by directly querying `Invoice.objects` with `get_object_or_404()`, circumventing the `IsInvoiceOwner` permission class. The declared permission is never applied because `has_object_permission()` is only invoked when using the ViewSet's `get_object()` method, not when manually fetching objects.

## Source

**File:** `views.py`, line 19-21

**Issue:** The custom `retrieve()` method overrides ModelViewSet's default retrieve and fetches the invoice directly without applying object-level authorization checks. The `IsInvoiceOwner` permission class declares `has_object_permission()` but this is only called when using DRF's `get_object()` method. By directly calling `get_object_or_404()`, the permission is bypassed.

**Call chain:** 
- `InvoiceViewSet.retrieve()` (line 19) calls
- `get_object_or_404()` (line 21) which queries `Invoice.objects` directly
- This bypasses `get_object()` which would call `check_object_permissions()`
- Result: `IsInvoiceOwner.has_object_permission()` is never invoked

## Fix

### File: views.py

```python
from django.shortcuts import get_object_or_404
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

The fix uses `self.get_object()` instead of `get_object_or_404()`. The `get_object()` method is DRF's standard way to fetch a single object and it:

1. **Applies the queryset filter** from `get_queryset()`, which restricts non-staff users to their own invoices.
2. **Invokes object-level permission checks** by calling `self.check_object_permissions()`, which runs `IsInvoiceOwner.has_object_permission()` before returning the object.
3. **Raises 404 automatically** if the object is not found or the user lacks permission (403 Forbidden for permission denial).

This ensures that both authentication (`IsAuthenticated`) and authorization (`IsInvoiceOwner`) are properly enforced in the `retrieve()` endpoint, preventing unauthorized access to other users' invoices.
