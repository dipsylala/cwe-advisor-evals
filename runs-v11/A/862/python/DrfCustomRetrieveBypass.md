## Verdict

Confirmed: Missing Authorization in custom `retrieve()` method.

## Source

The `retrieve()` method at line 19-26 in `views.py` bypasses the viewset's permission checks by directly calling `get_object_or_404(Invoice, pk=pk)` on line 21. Although `permission_classes = [IsAuthenticated, IsInvoiceOwner]` is declared at the viewset level, the custom method overrides the default DRF implementation and skips authorization entirely. The `IsInvoiceOwner.has_object_permission()` check is never invoked, allowing any authenticated user to retrieve invoices they do not own.

## Fix

Replace `get_object_or_404()` with `self.get_object()` in the `retrieve()` method. DRF's `get_object()` method integrates the full permission framework, including a call to `check_object_permissions()` that validates the retrieved object against the configured permission classes.

```python
def retrieve(self, request, pk=None):
    invoice = self.get_object()
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

The `pk` parameter is automatically passed to `get_object()` by DRF's router, so no explicit parameter is needed.

## Explanation

Django REST Framework's permission framework is only invoked when using DRF's built-in methods like `get_object()`, `list()`, `create()`, etc. When a custom method directly queries the database (via Django's `get_object_or_404()` or QuerySet methods), DRF's permission layer is bypassed entirely.

The `IsInvoiceOwner.has_object_permission()` method defines the authorization rule—only the invoice owner or staff can access an invoice—but this check is never reached when `get_object_or_404()` retrieves the object first.

Using `self.get_object()` ensures that:
1. The object is retrieved from the queryset (which filters by user if non-staff)
2. `check_object_permissions()` is called, validating against `IsInvoiceOwner`
3. A 403 Forbidden response is returned if authorization fails
4. The permission framework and business logic are unified
