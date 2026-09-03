## Verdict

Exploitable. An authenticated user can retrieve any invoice by ID, regardless of ownership, because the custom `retrieve()` method bypasses the object-level authorization check.

## Source

File: `evals/cases/862/python/DrfCustomRetrieveBypass/views.py`, line 21

The vulnerable sink is the direct call to `get_object_or_404(Invoice, pk=pk)` without any authorization verification. Although the `InvoiceViewSet` declares `permission_classes = [IsAuthenticated, IsInvoiceOwner]`, the custom `retrieve()` method overrides the default behavior and fetches the invoice without invoking the permission check.

## Fix

**Vulnerable code:**
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

**Fixed code:**
```python
def retrieve(self, request, pk=None):
    invoice = self.get_object()
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

## Explanation

The fix replaces the unfiltered `get_object_or_404(Invoice, pk=pk)` call with `self.get_object()`. In Django REST Framework, `self.get_object()` applies two critical authorization layers: it first applies the `get_queryset()` filtering (which restricts non-staff users to their own invoices), and then invokes the permission class's `has_object_permission()` method (which double-checks ownership). This ensures that the `IsInvoiceOwner` permission class is properly enforced. The method will now return 404 for users who do not own the invoice, eliminating the authorization bypass.

## Behaviour changes

- The custom `retrieve()` method now respects the DRF permission framework instead of bypassing it.
- Non-staff users will only be able to retrieve invoices they own (those where `invoice.owner_id == request.user.id`); staff users can retrieve any invoice.
- Requests for invoices the user cannot access will return 404 (via the scoped queryset lookup), rather than 200 with the invoice data.
- The `pk` parameter is no longer directly passed to the database query; it is filtered through `get_queryset()` first.
