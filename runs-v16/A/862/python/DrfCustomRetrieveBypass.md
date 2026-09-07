## Verdict

CONFIRMED — The overridden `retrieve` method bypasses object-level permission enforcement by using Django's `get_object_or_404()` instead of DRF's permission-aware `get_object()`. An authenticated user can access any Invoice regardless of ownership.

## Source

The `retrieve` method in `InvoiceViewSet` (line 21) fetches the object directly:

```python
invoice = get_object_or_404(Invoice, pk=pk)
```

The class declares `permission_classes = [IsAuthenticated, IsInvoiceOwner]`, where `IsInvoiceOwner.has_object_permission()` enforces the ownership check. However, by overriding `retrieve` without calling the parent's object-retrieval logic, the viewset bypasses the automatic permission checking that DRF provides.

The `IsInvoiceOwner` permission class defines the check correctly (`obj.owner_id == request.user.id`), but it is never invoked because `get_object_or_404` does not trigger DRF's permission machinery.

## Fix

Replace the direct `get_object_or_404()` call with DRF's `self.get_object()` method, which automatically applies all configured permissions:

```python
def retrieve(self, request, pk=None):
    invoice = self.get_object()
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

Alternatively, if you must use `get_object_or_404()`, manually invoke the permission check afterward:

```python
def retrieve(self, request, pk=None):
    invoice = get_object_or_404(Invoice, pk=pk)
    self.check_object_permissions(request, invoice)
    return Response({...})
```

The first approach is preferred because it is the standard DRF pattern and cleaner.

## Explanation

DRF's `ModelViewSet` provides a default `retrieve()` implementation that calls `self.get_object()`. This method looks up the object *and* applies both view-level and object-level permissions from `permission_classes`.

When you override `retrieve()` without using `self.get_object()`, you bypass that machinery. Django's `get_object_or_404()` is a low-level utility that only raises 404 on a missing object; it has no awareness of DRF permissions.

Using `self.get_object()` restores the permission checks. It will raise `PermissionDenied` if the object exists but fails the `IsInvoiceOwner` check, which is the correct behavior for a missing authorization condition.
