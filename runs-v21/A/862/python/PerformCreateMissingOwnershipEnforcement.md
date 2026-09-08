## Verdict
Confirmed. Line 23 in `perform_create()` calls `serializer.save()` without enforcing that the created ExpenseReport belongs to the current user. This allows authorization bypass: an authenticated user can create expense reports owned by any user, bypassing the `IsExpenseReportOwner` check applied only to object-level operations.

## Source
```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

The `serializer.save()` call does not pass the owner field, leaving it either unset or defaultable to an attacker-supplied value in the request data.

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
        # Enforce that the created ExpenseReport is owned by the current user.
        serializer.save(owner=self.request.user)
```

## Explanation
The fix sets the `owner` field to the authenticated user before saving the serializer. This enforces that newly created ExpenseReport objects always belong to the user who creates them, preventing any authenticated user from creating reports owned by others.

This pattern mirrors how `IsExpenseReportOwner` checks object ownership in retrieve/update/destroy operations, extending the same authorization boundary to the create operation. The ownership is now enforced at the model level during object creation, not just during subsequent access.
