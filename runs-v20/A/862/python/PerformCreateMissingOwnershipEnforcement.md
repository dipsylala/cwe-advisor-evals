## Verdict

Confirmed. `perform_create()` saves the new `ExpenseReport` with whatever attributes the serializer already carries, without binding the record to the authenticated requester. `IsExpenseReportOwner.has_object_permission()` only runs on `retrieve`/`update`/`destroy` via `get_object()` — there is no such object-level check on `create`, because the object doesn't exist yet. If the serializer exposes an owner-identifying field (directly or through a writable nested/FK field), a client can submit that field in the request body and create an expense report attributed to another user, or the record can end up with no enforced owner at all. Either way, the authorization the class docstring claims ("object-scoped ownership") never applies to creation, which is exactly the missing-authorization gap CWE-862 describes.

## Source

`perform_create(self, serializer)` in `views.py`, line 21 — invoked by DRF's `CreateModelMixin.create()` with a serializer already validated from the untrusted request body (`self.request.data`). Any writable owner-identifying field on `ExpenseReportSerializer` is attacker-controlled input at this point.

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
        # Force ownership to the authenticated requester. Any owner-identifying
        # value the client submitted in the request body is overridden here, so
        # a report can never be created on another user's behalf.
        serializer.save(owner=self.request.user)
```

## Explanation

`serializer.save(**kwargs)` merges its keyword arguments into `serializer.validated_data` and lets them win over any value already present there, so `serializer.save(owner=self.request.user)` unconditionally attributes the new `ExpenseReport` to the authenticated caller regardless of what the client put in the request body for that field. This closes the gap without touching the read/update/delete path: `IsExpenseReportOwner.has_object_permission()` continues to gate `retrieve`/`update`/`destroy` exactly as before, and `create` now gets the equivalent guarantee — the record can only ever be owned by its actual creator — enforced structurally at the point of creation rather than checked after the fact.

Verifying the fix: attempt to create an expense report while supplying an `owner`/`user` field in the payload that names a different user id; the persisted record should have `owner` equal to the authenticated requester regardless of the submitted value. A negative test — creating without any owner field supplied — should also result in the record being owned by the requester, confirming no code path leaves the object unowned.
