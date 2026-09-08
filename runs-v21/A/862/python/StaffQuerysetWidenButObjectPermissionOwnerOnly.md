## Verdict
Confirmed. CWE-862 (Missing Authorization).

## Source
The `get_queryset()` method on line 29-33 permits staff users to bypass the `IsTicketOwner` authorization check by returning all tickets without filtering. The object-level permission check in `IsTicketOwner.has_object_permission()` only executes during detail actions (retrieve/update/destroy), not list, leaving the list action unconstrained.

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
Removed the `is_staff` check from `get_queryset()`. All users, including staff, now receive only the tickets they own. This ensures the queryset respects the authorization policy stated in the docstring: only the owner (and the assigned agent, if that check is implemented in `IsTicketOwner`) can view a ticket.

The root cause was that `get_queryset()` widened access for staff users without any corresponding object-level check on the list action. Since `has_object_permission()` is only called during detail operations, the list action returned unfiltered rows. Removing the special case forces all users through the same owner filter, aligning `get_queryset()` with the declared policy and the permission class's design.
