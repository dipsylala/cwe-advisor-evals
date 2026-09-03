## Verdict
CONFIRMED - CWE-862 (Missing Authorization)

## Source
In `ExpenseReportViewSet.perform_create()`, the `serializer.save()` call at line 23 does not enforce ownership. The view's `permission_classes` include `IsExpenseReportOwner`, but that permission class only applies to object-scoped operations (retrieve, update, destroy) via `has_object_permission()`. During create, no object exists yet, so ownership cannot be checked against a non-existent record. An authenticated user can create an expense report owned by any user, bypassing the ownership authorization that protects subsequent operations.

## Fix
Set the owner field to the current authenticated user before saving:

```python
def perform_create(self, serializer):
    serializer.save(owner=self.request.user)
```

This ensures the created expense report is owned by the user who submitted it, making the ownership check in `IsExpenseReportOwner` enforceable on all subsequent operations (update, retrieve, destroy).

## Explanation
The `perform_create()` method is the point where object-level authorization must be enforced for the create action. By passing `owner=self.request.user` to `serializer.save()`, the newly created instance is bound to the authenticated user at creation time. This establishes the ownership invariant that `IsExpenseReportOwner.has_object_permission()` relies on for later operations. The fix is minimal and idiomatic for Django REST Framework: it delegates the ownership binding to the serializer layer while ensuring the authorization policy is consistent from the moment the object is created.
