## Verdict

Confirmed. `InvoiceViewSet.retrieve()` bypasses object-level authorization.

## Source

`pk` from the URL route (the DRF viewset's `retrieve(self, request, pk=None)` parameter), reaching `get_object_or_404(Invoice, pk=pk)` at line 21 in `views.py`.

## Fix

```python
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .models import Invoice
from .permissions import IsInvoiceOwner
from rest_framework.permissions import IsAuthenticated


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

The change replaces `get_object_or_404(Invoice, pk=pk)` with `self.get_object()`.

## Explanation

`ModelViewSet.get_object()` is DRF's standard object-lookup path: it looks the instance up through `self.get_queryset()` (already scoped to the caller's own invoices unless they are staff) and then calls `self.check_object_permissions(request, obj)`, which runs every configured permission's `has_object_permission()` — including `IsInvoiceOwner`, which is declared in `permission_classes` but never actually invoked by the vulnerable code.

The original `retrieve()` instead called `get_object_or_404(Invoice, pk=pk)` directly against the `Invoice` model manager, unfiltered and with no call to `check_object_permissions()`. DRF only runs object-level permission checks when a view explicitly calls `check_object_permissions()` (which `get_object()` does internally) — declaring a permission class in `permission_classes` only gets its `has_permission()` (view-level, e.g. "is authenticated") checked automatically; `has_object_permission()` is opt-in per lookup. Because the custom `retrieve()` skipped that call and queried the model directly instead of through the owner-filtered `get_queryset()`, any authenticated user could supply an arbitrary invoice `pk` and receive another user's invoice data (including `total_cents`), regardless of ownership or staff status.

Routing the lookup through `self.get_object()` restores both the queryset-level filter and the object-level `IsInvoiceOwner` check with a one-line change, and keeps the custom response shape intact.
