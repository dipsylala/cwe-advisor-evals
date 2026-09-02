## Verdict

Exploitable. The custom `retrieve()` method bypasses the authorization checks that would normally be enforced by the `IsInvoiceOwner` permission class.

## Source

HTTP GET request to the retrieve endpoint with a user-provided invoice ID (`pk` parameter). Any authenticated user can request any invoice ID.

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

The custom `retrieve()` method was bypassing Django REST Framework's permission framework by directly querying the database with `get_object_or_404(Invoice, pk=pk)` instead of using `self.get_object()`. The `IsInvoiceOwner` permission class's `has_object_permission()` method only runs when `self.get_object()` is called; the direct query skipped this check entirely. Replacing the direct query with `self.get_object()` ensures that DRF applies both the `get_queryset()` filtering (which limits invoices to the requesting user's own records, except for staff) and the `has_object_permission()` authorization check before returning the invoice. If the user is not authorized, `self.get_object()` raises a 404 response (scoped lookup approach, indistinguishable from "not found" to prevent enumeration).

## Behaviour changes

- `self.get_object()` applies `get_queryset()` filtering and `has_object_permission()` checks; the original direct query did not. No API contract change from the caller's perspective, but unauthorized users now receive 404 instead of 200.
- The `pk` parameter is no longer explicitly passed to the query; `self.get_object()` internally retrieves it from `self.kwargs['pk']`, the standard DRF mechanism. This is the correct pattern for ViewSet methods.
- None beyond authorization enforcement. The response structure, status codes on success, and response body remain identical for authorized requests.
