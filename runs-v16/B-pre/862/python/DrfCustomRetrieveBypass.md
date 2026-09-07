## Verdict
**CONFIRMED**: The vulnerability is real. The custom `retrieve()` method uses `get_object_or_404()` directly, which bypasses DRF's automatic object-level permission checks. Any authenticated user can retrieve invoices they do not own.

## Source
**File:** `views.py`, lines 19–26  
**Call chain:** `InvoiceViewSet.retrieve()` (line 19) → `get_object_or_404(Invoice, pk=pk)` (line 21)

The custom `retrieve()` override fetches the invoice by primary key without applying the `IsInvoiceOwner` object permission that DRF would normally enforce through `self.get_object()`.

## Fix
Replace the direct `get_object_or_404()` call with `self.get_object()`:

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
The ViewSet correctly declares `permission_classes = [IsAuthenticated, IsInvoiceOwner]` and implements proper ownership checks in `IsInvoiceOwner.has_object_permission()`. However, by overriding `retrieve()` and bypassing DRF's view layer, the custom implementation avoids calling `self.get_object()`.

`self.get_object()` does two things the fix requires:

1. **Applies queryset scoping:** Calls `get_queryset()` which filters based on user role (`is_staff` → all rows, regular user → only rows they own)
2. **Applies object-level permissions:** Calls `check_object_permissions(request, obj)` which invokes `IsInvoiceOwner.has_object_permission()`

Using `get_object_or_404(Invoice, pk=pk)` skips both checks and directly fetches any invoice that exists. The declared permission classes have no effect.

## Behaviour changes
- **Before:** Any authenticated user could retrieve any invoice via `GET /invoices/{id}/`, regardless of ownership.
- **After:** Users can only retrieve their own invoices; staff can retrieve any invoice (as scoped by `get_queryset()` and gated by `has_object_permission()`). Unauthenticated users receive 401; unauthorized users (authenticated but lacking ownership) receive 404.
