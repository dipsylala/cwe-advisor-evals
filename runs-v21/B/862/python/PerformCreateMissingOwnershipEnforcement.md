## Verdict

CWE-862 confirmed and remediable.

## Source

**File**: views.py, line 23, in `ExpenseReportViewSet.perform_create()`

**Vulnerable code**:
```python
def perform_create(self, serializer):
    serializer.save()
```

The method creates a new ExpenseReport without enforcing that the owner is the authenticated user. A client-supplied `owner` field in the POST request is persisted as-is, allowing any authenticated user to create expense reports owned by other users.

**Data flow**:
1. Client sends POST with JSON including an untrusted `owner` field (source)
2. DRF deserializes to serializer, including the supplied owner value
3. `serializer.save()` (sink) persists the record with that owner
4. `IsExpenseReportOwner.has_object_permission()` never runs for create (only for retrieve/update/destroy via `get_object()`)

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
    create is scoped by perform_create() setting owner=request.user.
    """

    queryset = ExpenseReport.objects.all()
    serializer_class = ExpenseReportSerializer
    permission_classes = [IsAuthenticated, IsExpenseReportOwner]

    def perform_create(self, serializer):
        # Enforce ownership: creator is always the authenticated user
        serializer.save(owner=self.request.user)
```

### File: serializers.py

```python
from rest_framework import serializers

from .models import ExpenseReport


class ExpenseReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseReport
        fields = ["id", "owner", "description", "amount_cents", "status", "created_at"]
        read_only_fields = ["id", "owner", "status", "created_at"]
```

## Explanation

The vulnerability exists because `perform_create()` does not enforce ownership. While `IsExpenseReportOwner.has_object_permission()` blocks retrieve/update/delete on records not owned by the requester, it never runs for create—because create does not call `get_object()`.

The fix enforces ownership at the point of creation by passing `owner=self.request.user` to `serializer.save()`. This ensures the authenticated user is always set as the owner, regardless of what the client sends in the request body. Additionally, marking `owner` as read-only in the serializer prevents the client from attempting to override it—the field is visible but not settable.

This follows DRF's documented pattern for object-level authorization on create: since `get_object()` is not called, the check must be enforced in `perform_create()` or the serializer. The `request.user` source is server-controlled and trustworthy, whereas any client-supplied value is untrusted and must not be used for authorization decisions.

## Behaviour changes

- **Create endpoint now enforces ownership**: An authenticated user creating an expense report will have themselves set as the owner. Previously, they could specify any user as the owner.
- **POST requests attempting to set owner are now ignored**: Clients cannot override the owner field. If clients were previously setting owner in requests, those values are now discarded in favor of the authenticated user's ID.
- **Serializer prevents client control of owner**: The `owner` field is visible in read operations but cannot be written via POST/PUT/PATCH, closing the client-side override path and making the enforcement visible in API documentation.
- **No change to retrieve/update/delete**: These operations continue to use `IsExpenseReportOwner.has_object_permission()` as before, rejecting access to records not owned by the requester.
