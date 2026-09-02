## Verdict

Real. The custom `retrieve()` method bypasses authorization checks by directly querying the database without validating that the authenticated user owns or has permission to access the requested invoice.

## Source

**File:** `views.py`, line 21

The `retrieve()` method overrides the default Django REST framework behavior and uses `get_object_or_404(Invoice, pk=pk)` to fetch an invoice by its primary key. This query is executed without invoking the `IsInvoiceOwner` permission check defined in `permission_classes`, allowing any authenticated user to retrieve any invoice by guessing or enumerating invoice IDs.

The `IsInvoiceOwner` permission class (in `permissions.py`) correctly implements `has_object_permission()` to verify that the requesting user is either staff or the invoice owner, but this check is never executed because the `retrieve()` method bypasses it.

## Fix

```python
def retrieve(self, request, pk=None):
    invoice = get_object_or_404(Invoice, pk=pk)
    self.check_object_permissions(request, invoice)
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

Alternatively, use the DRF built-in approach by removing the custom `retrieve()` method entirely and allowing the default implementation to run, which automatically applies permission checks. If you must override, call `self.check_object_permissions(request, invoice)` immediately after fetching the object to validate authorization before returning data.

## Explanation

Django REST framework's default `retrieve()` implementation calls `get_object()`, which in turn calls `check_object_permissions()` to verify that the authenticated user has access to the retrieved object. By replacing this with a direct `get_object_or_404()` call, the custom method silently disables the permission check.

The fix adds an explicit call to `self.check_object_permissions(request, invoice)` to enforce the `IsInvoiceOwner` permission rule. This raises a `PermissionDenied` exception (HTTP 403) if the user is neither staff nor the invoice owner, preventing unauthorized access.

Without this check, an attacker can iterate through invoice IDs to enumerate and retrieve all invoices in the system, violating the intended access control that restricts each non-staff user to their own invoices.
