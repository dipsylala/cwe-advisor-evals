## Verdict

CWE-862 (Missing Authorization) is confirmed. The `perform_create()` method creates an ExpenseReport without enforcing ownership - any authenticated user can create a report and, without the owner constraint, could potentially create reports for other users.

## Source

File: `evals/cases/862/python/PerformCreateMissingOwnershipEnforcement/views.py`

The data flow:
1. An authenticated user sends a POST request to create an expense report.
2. DRF's `create()` method validates the request data via the serializer.
3. `perform_create()` is invoked with the validated serializer.
4. Line 23: `serializer.save()` persists the ExpenseReport to the database.
5. The view-level `permission_classes = [IsAuthenticated, IsExpenseReportOwner]` verify authentication, but `IsExpenseReportOwner.has_object_permission()` is never invoked during create because `get_object()` is never called for POST operations.
6. Result: The ExpenseReport is created without an owner constraint, breaking the intended access control model where only the owning user should be able to manipulate their own reports.

## Fix

**Vulnerable code (line 23):**
```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

**Fixed code:**
```python
def perform_create(self, serializer):
    serializer.save(user=self.request.user)
```

## Explanation

The fix sets the `user` field to the authenticated request user before persisting the ExpenseReport. This enforces the ownership constraint: only the authenticated user creating the report can be its owner. DRF's `serializer.save()` accepts keyword arguments that are passed to the model's `save()` method or used to populate fields during instance creation. By passing `user=self.request.user`, the view ensures that every ExpenseReport created contains the correct owner reference, which allows `IsExpenseReportOwner.has_object_permission()` to correctly authorize retrieve/update/destroy operations on subsequent requests.

This approach aligns with the standard DRF pattern for enforcing object-level ownership constraints on create operations, since the permission class's `has_object_permission()` is not automatically invoked during resource creation.

## Behaviour changes

- **Before**: Any authenticated user calling POST can create an ExpenseReport; the created object has no enforced owner field value, leaving the resource unowned or externally specified.
- **After**: Any authenticated user calling POST creates an ExpenseReport with their own user ID as the owner. Subsequent retrieve/update/destroy operations respect the ownership check via `IsExpenseReportOwner.has_object_permission()`.
- **Impact**: The integrity of the expense report access control model is restored. Users cannot create reports on behalf of other users or manipulate reports they do not own.
