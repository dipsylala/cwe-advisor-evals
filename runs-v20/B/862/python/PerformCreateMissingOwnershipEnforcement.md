## Verdict

Confirmed. `perform_create()` calls `serializer.save()` with no owner binding, and `ExpenseReportSerializer.owner` is not in `read_only_fields`, so an authenticated caller can POST an arbitrary `owner` id and create an `ExpenseReport` attributed to another user. `IsExpenseReportOwner.has_object_permission()` never runs on create - DRF only invokes object-level permission checks via `get_object()`, which the create path does not call - so nothing else in the class stops it.

## Source

Request body field `owner`, deserialized by `ExpenseReportSerializer` (writable, not read-only) into `serializer.validated_data`, reaching the sink unmodified.

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
        # Object-level permissions never run on create (get_object() isn't called),
        # so ownership is enforced here: save() kwargs override any client-supplied
        # value in validated_data, including a spoofed "owner" in the request body.
        serializer.save(owner=self.request.user)
```

## Explanation

`perform_create()` is the DRF-documented place to bind server-controlled values on create, because `has_object_permission()` is never evaluated for POST - there is no existing instance for `get_object()` to fetch. `BaseSerializer.save(**kwargs)` merges its keyword arguments into `validated_data` before calling `create()`, and those kwargs take precedence over whatever the client submitted for the same field. Passing `owner=self.request.user` therefore forces the report's owner to the authenticated caller regardless of any `owner` value present in the request body, closing the missing-authorization gap without touching the serializer's field configuration, the permission classes, or the retrieve/update/destroy paths, which were already correctly scoped.

## Behaviour changes

- A client-supplied `owner` value in the POST body is now silently overridden with the authenticated caller's id instead of being honored. Any legitimate caller that relied on setting `owner` explicitly (e.g. an admin creating a report on behalf of another user) will need a separate, explicitly authorized path - this fix does not add one, since the finding and existing permission model give no indication such a capability was intended.
- No change to response codes, to `retrieve`/`update`/`destroy` behavior, or to the `permission_classes` list.
