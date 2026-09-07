## Verdict

CONFIRMED. Missing object-level authorization enforcement on create. The `perform_create()` method bypasses the `IsExpenseReportOwner` permission class by not enforcing ownership of the newly created ExpenseReport, allowing any authenticated user to create reports without verification they own them.

## Source

**File**: views.py  
**Line**: 23 (`serializer.save()`)  
**Method**: `ExpenseReportViewSet.perform_create()`  
**Vulnerability**: DRF's object-level permission checks do not run during create operations because `get_object()` is never called. The current code passes no ownership information to `serializer.save()`, creating an ExpenseReport with unverified ownership.

**Call chain**:
1. Authenticated POST request to `/expensereports/` endpoint
2. Routed to `ExpenseReportViewSet.create()`
3. DRF calls `perform_create(serializer)` after validation
4. Line 23 calls `serializer.save()` with no owner enforcement
5. ExpenseReport is created with arbitrary or unset owner

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
        # Enforce ownership: new ExpenseReport must be owned by the requesting user.
        # Object-level permissions do not run on create (no get_object() call), so the
        # ownership constraint is enforced here instead, per DRF guidance.
        serializer.save(owner=self.request.user)
```

## Explanation

The fix adds object-level ownership enforcement to the create operation by passing `owner=self.request.user` to `serializer.save()`. This ensures that every newly created ExpenseReport is owned by the authenticated user making the request.

Without this change, an authenticated user could create ExpenseReport records without any verification of ownership - either creating reports for other users or creating orphaned records. The `IsExpenseReportOwner` permission class protects retrieve/update/delete operations through `has_object_permission()`, but that check runs only when `get_object()` is called, which never happens during create.

By enforcing ownership at the serializer level during `perform_create()`, the fix applies the same ownership constraint that the permission class enforces on other operations, closing the authorization gap on the create path.

## Behaviour changes

- **User impact**: Authenticated users can now create ExpenseReport records only for themselves; the `owner` field is automatically set to the requesting user.
- **Validation**: DRF's `IsAuthenticated` permission still gates the endpoint (rejects unauthenticated requests with 401). The fix adds the missing object-level constraint.
- **Response**: The API response from a successful POST remains the same; the created ExpenseReport now includes the user's ID as the owner.
- **Testing**: A test that calls POST as authenticated user A should now see ExpenseReports with `owner=A`. A subsequent attempt to modify the report by another user B (via update/delete) continues to be rejected by `IsExpenseReportOwner.has_object_permission()`.
