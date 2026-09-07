## Verdict

Real. The custom `retrieve` method bypasses both queryset filtering and permission checks that should restrict access to owned invoices.

## Source

File: `views.py`, lines 19–26

```python
def retrieve(self, request, pk=None):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    invoice = get_object_or_404(Invoice, pk=pk)
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

The vulnerability: `get_object_or_404(Invoice, pk=pk)` queries the Invoice table directly by primary key without applying the queryset filter from `get_queryset()` (which restricts non-staff users to their own invoices) or the permission check from `IsInvoiceOwner` (which enforces ownership at the object level). An unauthenticated or unprivileged user can fetch any invoice by ID.

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
        # Use self.get_object() to apply queryset filtering and permission checks
        invoice = self.get_object()
        return Response({
            "id": invoice.id,
            "owner_id": invoice.owner_id,
            "total_cents": invoice.total_cents
        })
```

## Explanation

The custom `retrieve` method overrides the default DRF behavior and must explicitly enforce authorization. The fix uses `self.get_object()` instead of `get_object_or_404(Invoice, pk=pk)`.

`self.get_object()` is DRF's standard method for safely retrieving a single object; it:
1. Calls `self.get_queryset()` to get the filtered queryset (which restricts non-staff users to their own invoices)
2. Looks up by the configured lookup field (default: 'pk')
3. Calls `self.check_object_permissions(request, obj)` to invoke the `IsInvoiceOwner` permission class, which verifies the user is staff or the invoice owner

This restores the authorization logic that the custom override bypassed, ensuring only the invoice owner (or staff) can retrieve it.
