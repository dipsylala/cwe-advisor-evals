## Verdict
exploitable

## Source
`self.request.user` – the authenticated request user, available via DRF's request object in `perform_create()`.

## Fix

**Vulnerable code:**
```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

**Fixed code:**
```python
def perform_create(self, serializer):
    serializer.save(owner=self.request.user)
```

## Explanation
The vulnerability exists because `perform_create()` does not enforce that the newly created ExpenseReport is owned by the authenticated user. While the viewset declares `IsExpenseReportOwner` as a permission class, object-level permissions in DRF (via `has_object_permission()`) only run when `get_object()` is called—which happens for retrieve/update/destroy operations, not for create. An authenticated user could theoretically create an expense report and assign ownership to another user, bypassing the authorization check that protects retrieve/update/delete operations.

The fix explicitly sets the `owner` field to the current user before saving, ensuring that newly created objects are always owned by the requesting user. This enforces the same ownership relationship at the point of creation that the `IsExpenseReportOwner` permission class verifies for subsequent operations.

## Behaviour changes
The `serializer.save()` call now receives an additional keyword argument `owner=self.request.user`. This argument is passed to the serializer's `create()` method and used to set the object's owner field before it is written to the database. The serializer must accept an `owner` parameter in its `create()` method or have `owner` as a writable field in its declared `fields`; this is standard in DRF when implementing ownership-based access control and matches the pattern expected by `IsExpenseReportOwner.has_object_permission()` during later operations.
