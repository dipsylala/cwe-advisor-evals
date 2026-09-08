## Verdict
Confirmed. `retrieve()` fetches the `Invoice` directly from the unfiltered model manager instead of going through DRF's object-lookup machinery, so it bypasses both the ownership scoping in `get_queryset()` and the `has_object_permission()` check in `IsInvoiceOwner`. Any authenticated user who supplies another user's invoice `pk` gets that invoice's data back.

## Source
`request` (the `pk` URL kwarg supplied by the caller) reaching `retrieve(self, request, pk=None)` in `views.py`.

## Fix
The sink is `get_object_or_404(Invoice, pk=pk)` on line 21 of `views.py`: it queries `Invoice` directly, ignoring `self.get_queryset()` (which restricts non-staff users to their own invoices) and never invokes `self.check_object_permissions()` (which would run `IsInvoiceOwner.has_object_permission()`). Replacing it with DRF's own `self.get_object()` restores both checks, since `GenericAPIView.get_object()` looks the record up through `self.filter_queryset(self.get_queryset())` and then calls `self.check_object_permissions(self.request, obj)` before returning it.

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
`ModelViewSet.get_object()` (inherited from `GenericAPIView`) is the standard DRF entry point for a detail-view lookup: it builds the filter from `self.get_queryset()` combined with the URL kwarg named by `lookup_url_kwarg`/`lookup_field` (`pk` by default), runs `get_object_or_404()` against that filtered queryset, and then calls `self.check_object_permissions(self.request, obj)`, which iterates `permission_classes` and invokes any `has_object_permission()` they define - here, `IsInvoiceOwner.has_object_permission()`. The vulnerable code skipped straight to `get_object_or_404(Invoice, pk=pk)` against the bare model manager, so neither the ownership-scoped queryset nor the object-level permission ever ran; only the view-level `IsAuthenticated` check applied, which only confirms the caller is logged in, not that they own the requested invoice. Using `self.get_object()` closes the gap with no change to the response body or the URL/routing contract, and it composes correctly with `get_queryset()` already returning `Invoice.objects.all()` for staff - staff continue to reach any invoice, and non-staff are now confined to rows their own filtered queryset would have returned, with `has_object_permission()` as a second, explicit check on top of that. No import removal was needed beyond dropping the now-unused `get_object_or_404` import.
