## Verdict

exploitable

## Source

The `pk` parameter from the URL is passed directly to `get_object_or_404(Invoice, pk=pk)` in the custom `retrieve()` method without applying the object ownership check.

## Fix

**Vulnerable code (line 19-26):**
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

The fix replaces the direct `get_object_or_404(Invoice, pk=pk)` call with `self.get_object()`, which is DRF's built-in method that applies both the queryset scoping from `get_queryset()` and the object-level permission check from `has_object_permission()`. This ensures that non-staff users can only retrieve invoices they own. The `get_queryset()` method already filters to `owner_id=self.request.user.id` for non-staff users and returns all invoices for staff, while `IsInvoiceOwner.has_object_permission()` verifies ownership. By using `self.get_object()`, both protections are applied, and any attempt to access an invoice the user does not own will result in a 404 response rather than a 200 with unauthorized data.

## Behaviour changes

The fix changes the lookup from an unrestricted direct query to a scoped query that incorporates the user's authorization context. Previously, `get_object_or_404(Invoice, pk=pk)` would fetch any invoice in the database by its ID. After the fix, `self.get_object()` first applies `get_queryset()` to scope the query to the user's own invoices (or all invoices for staff), then applies the `has_object_permission()` check, ensuring non-staff users receive a 404 when attempting to access another user's invoice rather than a 200 with their data exposed. The response contract is preserved: the method still returns a 200 with the invoice data on successful authorization or a 404 on failure.
