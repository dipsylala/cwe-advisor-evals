## Verdict

The `perform_create()` method saves the expense report without enforcing that the authenticated user is the owner. Authorization is missing: any authenticated user can create reports they do not own, bypassing the `IsExpenseReportOwner` check that protects retrieve/update/destroy.

## Source

```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

The `perform_create()` method is called by Django REST Framework's `create()` action after validation. It receives a serializer whose `validated_data` has not been bound to the request context. The caller does not automatically receive ownership of the created object.

## Fix

```python
def perform_create(self, serializer):
    serializer.save(owner=self.request.user)
```

Pass the authenticated user as the `owner` field to `serializer.save()`. Django REST Framework calls `perform_create()` only after verifying `IsAuthenticated`, so `self.request.user` is guaranteed to be an authenticated user object. The serializer's `create()` method will assign this user to the new `ExpenseReport` instance before saving it to the database.

## Explanation

The class checks `IsAuthenticated` at the view level, but ownership is not automatically bound. Without explicit assignment in `perform_create()`, a CREATE request creates a report with a `null` or uninitialized `owner` field. The `IsExpenseReportOwner` permission guards retrieve/update/destroy by checking `has_object_permission()`, which is never called during create—it only applies to object-scoped actions.

By setting `owner=self.request.user` in `perform_create()`, the new report is owned by the requester, and all subsequent access to it (update, delete) enforces ownership correctly through the same permission class.
