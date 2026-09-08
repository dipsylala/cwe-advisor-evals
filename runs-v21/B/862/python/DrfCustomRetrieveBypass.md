## Verdict
The finding is confirmed. The custom `retrieve()` method directly calls `get_object_or_404(Invoice, pk=pk)` without any authorization check, allowing any authenticated user to fetch any invoice by primary key regardless of ownership. The `IsInvoiceOwner` permission class is declared but bypassed by the hand-written `get_object_or_404()` call, which does not trigger DRF's object-level permission framework.

## Source
The vulnerability source is the request path: an authenticated user supplies a `pk` parameter in the URL to the `retrieve()` endpoint, which is then used directly in the database lookup.

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
The fix replaces the direct `get_object_or_404(Invoice, pk=pk)` call with `self.get_object()`, which is the standard Django REST Framework method that enforces both authorization layers: the queryset-level filter (via `get_queryset()`) and the object-level permission check (via `check_object_permissions()`). This ensures that:

1. Non-staff users can only retrieve invoices they own, because `get_queryset()` filters to `owner_id=self.request.user.id`
2. The `IsInvoiceOwner.has_object_permission()` check runs, confirming the user has access to the specific object
3. An unauthorized user receives a 404 response (from the scoped queryset), not a 403, which prevents the endpoint from confirming invoice existence and turning the ID space into an enumeration oracle

The fix preserves the existing authorization logic without modifying it, and does not change the response structure or the endpoint's public contract - only its access control.

## Behaviour changes
- Authenticated non-staff users can now only retrieve invoices they own, whereas before they could retrieve any invoice by ID
- Users who do not own an invoice receive 404 (via the scoped queryset) rather than 200 with invoice data
- Staff users retain the ability to retrieve any invoice (unchanged - `get_queryset()` returns all invoices for staff)
- The permission framework is now consistently enforced across all retrieve operations
