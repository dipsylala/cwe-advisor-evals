## Verdict
CONFIRMED — Missing authorization check in custom retrieve method.

## Source
The vulnerability is at line 21 in `views.py`. The `retrieve()` method overrides the default DRF retrieve behavior and calls `get_object_or_404(Invoice, pk=pk)` directly, bypassing the queryset filtering that would normally enforce ownership checks.

The permission class `IsInvoiceOwner` is defined in the class's `permission_classes` but is not applied to this custom method because DRF's automatic permission-checking flow is bypassed when you override a method and implement your own data access logic.

## Fix
Replace the retrieve method to use the filtered queryset from `get_queryset()`:

```python
def retrieve(self, request, pk=None):
    invoice = get_object_or_404(self.get_queryset(), pk=pk)
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

This ensures that the queryset is filtered by ownership (for non-staff users) before attempting to retrieve the object, enforcing the authorization check.

## Explanation
The `get_queryset()` method correctly filters invoices: staff users see all invoices, but regular users only see invoices they own (where `owner_id == self.request.user.id`). However, the custom `retrieve()` method circumvents this by directly querying `Invoice` without any filter, allowing any authenticated user to access any invoice by its primary key.

The fix makes the custom retrieve method respect the queryset filtering defined in `get_queryset()`, which serves as the authorization boundary for this viewset. This is the standard DRF pattern for maintaining authorization in custom methods that override default behavior.
