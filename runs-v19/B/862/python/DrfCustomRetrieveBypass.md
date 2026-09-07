## Verdict
exploitable

## Source
The `pk` URL parameter passed to the `retrieve()` method.

## Sink
`get_object_or_404(Invoice, pk=pk)` at views.py line 21.

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
The vulnerability is that the custom `retrieve()` method uses `get_object_or_404(Invoice, pk=pk)` to fetch the invoice directly by primary key, which bypasses both the queryset scoping from `get_queryset()` and the permission check from the `IsInvoiceOwner.has_object_permission()` method. An authenticated but unprivileged user can access any invoice by guessing its pk, even if they do not own it.

The fix replaces `get_object_or_404(Invoice, pk=pk)` with `self.get_object()`, which is the standard DRF pattern for object retrieval in ViewSet methods. `self.get_object()` applies the queryset scoping from `get_queryset()` (which filters to the user's own invoices for non-staff) and automatically calls `self.check_object_permissions()`, which invokes the permission class's `has_object_permission()` method to verify ownership. The response format remains unchanged.

## Behaviour changes
None. The only change is replacing an unfiltered direct lookup with a scoped, permission-checked lookup. The response contract is preserved: the same fields are returned, same HTTP status codes apply (404 for missing or unauthorized, 200 for success, 401 for unauthenticated). The `IsInvoiceOwner` permission class already existed in the configuration, so the fix enforces what was already declared but not applied to this endpoint.
