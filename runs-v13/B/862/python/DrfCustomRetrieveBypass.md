## Verdict

This is a real authorization bypass. The custom `retrieve()` method bypasses Django REST Framework's automatic object permission checking, allowing any authenticated user to fetch any invoice by guessing its ID.

## Source

File: `views.py`, lines 19–26

The `retrieve()` method overrides DRF's default implementation and uses `get_object_or_404(Invoice, pk=pk)` to fetch the invoice. This direct query bypass both:
1. The `get_queryset()` filtering that scopes queries to the owner
2. The `check_object_permissions()` call that enforces the `IsInvoiceOwner` permission

The `IsInvoiceOwner` permission class defines `has_object_permission()` correctly (checks `obj.owner_id == request.user.id`), but it is never invoked because the custom `retrieve()` does not route through `self.get_object()`.

## Fix

Replace the custom `retrieve()` method to use `self.get_object()`, which automatically applies both queryset scoping and object permission checks:

```python
def retrieve(self, request, pk=None):
    invoice = self.get_object()
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

Alternatively, if you must use `get_object_or_404()`, manually add the permission check after fetching:

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

The first approach is preferred because `self.get_object()` also applies the `get_queryset()` scoping, which returns 404 for unauthorized access (not 403), preventing enumeration of invoice IDs that belong to other users.

## Explanation

`self.get_object()` applies two layers of access control:
1. **Queryset scoping**: The `get_queryset()` method filters invoices by owner (or returns all if staff), so the lookup itself is scoped. An unauthenticated or non-owning user's query returns no results, and `get_object()` raises 404.
2. **Object-level permission check**: After fetching, `self.get_object()` automatically calls `self.check_object_permissions()`, which invokes `IsInvoiceOwner.has_object_permission()` to verify ownership. If the check fails, it raises 403 Forbidden.

Using `get_object_or_404()` instead skips both layers, creating the authorization gap. The `permission_classes` setting is applied to the viewset, but the custom `retrieve()` method never triggers the framework's permission enforcement.

## Behaviour changes

- An authenticated non-owner user will receive 404 (from scoped queryset) instead of 200 with another user's invoice data
- Staff users continue to see all invoices as before (no change in behavior for authorized callers)
- The endpoint now honors the `IsInvoiceOwner` permission class that was declared but ineffective in the original code
