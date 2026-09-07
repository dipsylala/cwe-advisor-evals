## Verdict
CWE-862 confirmed. Staff accounts can list all customer tickets without authorization check.

## Source
`get_queryset()` returns `Ticket.objects.all()` for staff users, bypassing the owner/assignment authorization that `IsTicketOwner` is meant to enforce. The permission class's `has_object_permission()` only runs on retrieve/update/destroy, not on list actions, leaving the queryset-level authorization gap.

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
Removed the `is_staff` conditional that returned all tickets without authorization. All users—staff or not—now see only tickets they own. The `IsTicketOwner` permission class enforces the full authorization model: owner access on all operations and assignment-based access on retrieve/update/destroy. This prevents staff from using queryset widening to bypass object-level permission checks on list operations.

