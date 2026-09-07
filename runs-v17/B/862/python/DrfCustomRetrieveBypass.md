## Verdict

**Confirmed.** The `retrieve()` method bypasses authorization checks by directly calling `get_object_or_404()` instead of routing through DRF's `self.get_object()`, which is the sole point where `has_object_permission()` executes and where `get_queryset()` scoping applies. An authenticated user can access invoices they do not own.

## Source

The vulnerability appears in `views.py` line 21. The `InvoiceViewSet` declares `permission_classes = [IsAuthenticated, IsInvoiceOwner]` and defines `get_queryset()` to scope queries by owner for non-staff users, but the custom `retrieve()` method bypasses both protections:

```python
def retrieve(self, request, pk=None):
    invoice = get_object_or_404(Invoice, pk=pk)  # Bypasses checks
    return Response({...})
```

When a custom `retrieve()` method calls `get_object_or_404()` directly, it:
1. Ignores the `get_queryset()` filter that would exclude invoices the user does not own
2. Skips the `has_object_permission()` check from `IsInvoiceOwner`, which verifies `obj.owner_id == request.user.id`

The data flow is: authenticated request → `retrieve()` directly fetches by pk alone → response with full invoice details, regardless of ownership.

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

Replace `get_object_or_404(Invoice, pk=pk)` with `self.get_object()`. DRF's `get_object()` method applies two protections that the direct lookup omits:

1. **Queryset scoping**: `get_object()` uses the result of `get_queryset()`, which filters invoices to those owned by the requesting user (for non-staff). A staff user still sees all invoices. This ensures the lookup fails with 404 for invoices not owned by the caller.

2. **Object-level permission check**: `get_object()` automatically calls `check_object_permissions()`, which runs the `IsInvoiceOwner.has_object_permission()` method. This redundantly verifies the ownership relationship before returning the object.

The fix routes the retrieval through DRF's standard flow, which combines the queryset filter and the object permission check. An authenticated user lacking ownership of the requested invoice now receives 404 instead of the invoice details.

## Behaviour changes

- **Authorized users**: Staff users and invoice owners continue to retrieve their own invoices with 200 and full details.
- **Unauthorized users**: Authenticated users without the requested invoice's ownership now receive 404 instead of 200 with the invoice data. No longer can one user enumerate or access another user's invoices.
- **Unauthenticated users**: Remain denied at the `IsAuthenticated` gate, returning 401.
