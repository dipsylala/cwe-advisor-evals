## Verdict

The finding is valid. The `perform_create()` method in `ExpenseReportViewSet` lacks object-level authorization enforcement. While the ViewSet declares `IsExpenseReportOwner` in its permission classes, this custom permission only enforces ownership checks during retrieve/update/delete operations via `has_object_permission()`. The create action bypasses object-level authorization because no object exists yet when `perform_create()` runs, allowing an authenticated user to create an ExpenseReport without the owner field being set to the requesting user.

## Source

**File**: `views.py`, line 23

**Vulnerable pattern**:
```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

**Data flow**: 
1. POST request received by ViewSet's create action
2. `IsAuthenticated` permission check passes if user is logged in
3. `perform_create()` is called with the serializer
4. `serializer.save()` is called without passing the owner field
5. The newly created ExpenseReport has no owner assigned server-side, or the serializer relies on untrusted client data to set it

**Root cause**: The object-level permission class `IsExpenseReportOwner` requires `get_object()` to be called, which happens in retrieve/update/delete but never in create. Per DRF design, object-level authorization for create actions must be enforced explicitly in `perform_create()`.

## Fix

### File: views.py

```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import ExpenseReport
from .permissions import IsExpenseReportOwner
from .serializers import ExpenseReportSerializer


class ExpenseReportViewSet(viewsets.ModelViewSet):
    """
    Expense report submission and review.

    retrieve/update/destroy are object-scoped: IsExpenseReportOwner.has_object_permission()
    runs via ModelViewSet.get_object() and rejects any report the requester doesn't own.
    """

    queryset = ExpenseReport.objects.all()
    serializer_class = ExpenseReportSerializer
    permission_classes = [IsAuthenticated, IsExpenseReportOwner]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
```

## Explanation

The fix adds the missing object-level authorization enforcement for the create action by explicitly setting the owner field to the current authenticated user when saving the ExpenseReport. This ensures that:

1. **Ownership is server-enforced, not client-controllable**: The `owner` field is set on the server side via `self.request.user`, preventing an authenticated attacker from creating reports owned by other users or with no owner at all.

2. **Consistent with framework design**: Per DRF's own guidance, object-level permissions on create actions must be enforced in `perform_create()` since no object exists when authorization checks run. The `IsExpenseReportOwner.has_object_permission()` check applies automatically on subsequent retrieve/update/delete operations via the standard `get_object()` flow.

3. **Closes the authorization gap**: The ViewSet already declares the correct permission classes; the fix implements their intent for the create pathway. Subsequent access to the newly created report is now properly gated by the existing `IsExpenseReportOwner` permission class.

## Behaviour changes

**User-facing behavior**:
- When an authenticated user creates an expense report via POST, the report is automatically assigned to that user as the owner.
- This matches the existing behavior of retrieve/update/delete, where users can only access reports they own.
- No change to response codes or API contracts—the same 201 Created is returned.

**Security behavior**:
- An authenticated user can no longer create an ExpenseReport without being its owner.
- An authenticated user cannot create an ExpenseReport owned by another user.
- The authorization model is now consistent: all operations (create, retrieve, update, delete) enforce the same ownership constraint.
