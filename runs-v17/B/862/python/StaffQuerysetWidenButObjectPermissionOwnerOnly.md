## Verdict

**CONFIRMED.** The `get_queryset()` method returns all tickets for staff users without any authorization check, bypassing the declared `IsTicketOwner` permission class on list actions. Object-level permissions in DRF run only during `get_object()` calls (retrieve/update/destroy), not during list; the queryset scope is the only gate. Fixing the queryset scope closes the gap.

## Source

E:/Github/cwe-advisor/evals/cases/862/python/StaffQuerysetWidenButObjectPermissionOwnerOnly/views.py, line 32: `return Ticket.objects.all()` in the `is_staff` branch of `get_queryset()`.

## Fix

### File: views.py

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from .models import Ticket
from .permissions import IsTicketOwner


class TicketViewSet(ModelViewSet):
    """Support tickets. Product policy is that a ticket - which carries a
    customer's raw message body - is visible only to the customer who
    filed it, plus whichever single agent it has been explicitly assigned
    to (assignment happens through a separate endpoint, not modeled here).
    IsTicketOwner is meant to be the one and only access rule for this
    resource.

    is_staff was widened into get_queryset() while copying the pattern
    from AdminAuditLogViewSet, where every staff member is genuinely
    meant to see every row. Nobody reconciled that with IsTicketOwner's
    contract here: has_object_permission() only runs from self.get_object()
    (retrieve/update/destroy), so it never constrains what this list
    action returns, and every staff account - support, sales, whatever
    role - now lists every customer's ticket body regardless of
    assignment.
    """

    serializer_class = None
    permission_classes = [IsAuthenticated, IsTicketOwner]

    def get_queryset(self):
        return Ticket.objects.filter(owner=self.request.user)
```

## Explanation

The vulnerability was an inconsistency between the declared authorization rule (`IsTicketOwner` in `permission_classes`) and what `get_queryset()` actually returns. DRF's generic list view calls `get_queryset()` and then iterates the result without calling `get_object()` or invoking `has_object_permission()`. The `is_staff` conditional that was copied from `AdminAuditLogViewSet` (where every staff member should see every row) was never adapted for `TicketViewSet`, where the policy is that tickets are visible only to the owner plus assigned agents.

The fix removes the `is_staff` branch entirely. Now all authenticated users—staff and non-staff alike—receive only tickets where `owner=self.request.user`. This makes the queryset scope consistent with the declared `IsTicketOwner` permission class, ensuring the "one and only access rule" is actually enforced.

The fix preserves DRF's existing contract:
- The method still returns a QuerySet (not materialized)
- The serializer iterates and processes the filtered results
- The `IsTicketOwner` permission class continues to enforce object-level checks on detail/update/delete via `get_object()`
- Authentication is still required by `IsAuthenticated`

## Behaviour changes

- **Staff users**: Will now see only tickets they own (filtered by `owner=self.request.user`), not all tickets in the system.
- **Non-staff users**: No change; they already received this filter.
- **List endpoint response**: Will be narrower (fewer tickets returned) for staff users who are not ticket owners.
- **Detail/update/delete operations**: No change; `IsTicketOwner.has_object_permission()` continues to govern access.

This is the intended policy: by removing the widened `is_staff` branch, the endpoint enforces the declared authorization rule consistently across all HTTP methods.
