## Verdict

CONFIRMED: CWE-862 (Missing Authorization) exists in the `perform_create` method at line 23. The newly created ExpenseReport lacks ownership enforcement, allowing the requester to create reports without validating they own the object being created.

## Source

The vulnerability is in `views.py`, lines 21-23. The `perform_create` method calls `serializer.save()` without passing the owner parameter, leaving the ownership field unset or allowing it to be controlled by the request data. While `IsExpenseReportOwner` permission is defined at class level, it only applies to object-scoped operations (retrieve/update/destroy via `get_object()`) and does not protect create, which bypasses ownership validation entirely.

The ExpenseReport model (models.py line 6-10) defines an owner ForeignKey, and the permission class (permissions.py lines 7-8) validates that `obj.owner_id == request.user.id`. The serializer (serializers.py line 9) includes owner in the writable fields, creating a path to ownership bypass if not explicitly enforced during create.

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
        # Enforce ownership: new reports must belong to the requesting user
        serializer.save(owner=self.request.user)
```

## Explanation

The fix sets the owner to the current user at the moment of creation, ensuring that new ExpenseReport objects are always bound to the user who created them. By passing `owner=self.request.user` to `serializer.save()`, the ownership enforcement moves from the object-level permission (which only guards retrieve/update/destroy) to the create operation itself, closing the authorization gap.

This pattern is idiomatic in Django REST Framework: `perform_create` is the hook where business logic for ownership or other resource-level constraints is enforced. The fix prevents a requester from:
- Creating an expense report without an owner
- Creating an expense report owned by another user (even if the serializer field is writable)

The change is minimal and surgical: it adds a single parameter to the save call, keeping the method focused on its single responsibility of enforcing that created objects belong to the requester.
