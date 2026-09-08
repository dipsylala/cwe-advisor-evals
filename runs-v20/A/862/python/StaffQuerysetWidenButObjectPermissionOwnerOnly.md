## Verdict

Confirmed. `TicketViewSet.get_queryset()` returns `Ticket.objects.all()` for any user with `is_staff` set, for every action the queryset backs - including `list`. `IsTicketOwner.has_object_permission()` is only invoked by `self.get_object()` (retrieve/update/destroy), so DRF never calls it for `list`. The `Ticket` model carries only `owner`, `subject`, `body`, `created_at` - there is no assignment field for staff to be scoped against - so the staff branch has no ownership or assignment check backing it at all. Any authenticated staff account (support, sales, or any other role carrying that flag) can list every customer's ticket, including the raw message body, regardless of who owns or is assigned to it.

## Source

`self.request.user` (the authenticated request's user, specifically its `is_staff` flag) in `TicketViewSet.get_queryset()`, `views.py` line 30.

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
    """

    serializer_class = None
    permission_classes = [IsAuthenticated, IsTicketOwner]

    def get_queryset(self):
        return Ticket.objects.filter(owner=self.request.user)
```

## Explanation

`get_queryset()` builds the result set for `list` before any per-object permission runs, so it is the only place authorization for that action can be enforced; `IsTicketOwner.has_object_permission()` only fires for `self.get_object()`-based actions and never sees the rows `list` returns. The `is_staff` branch was copied from a different viewset (`AdminAuditLogViewSet`) where "every staff member sees every row" is the actual policy, but that policy was never true for tickets - the stated contract is owner-only, plus a single assigned agent through a separate endpoint that this model does not implement. Since `Ticket` has no field recording an assignment, there is nothing for a staff-scoped queryset to filter on here; the only queryset consistent with the documented policy and the current schema is the owner filter already present on the non-staff path, made unconditional. This also removes the redundant object-level check that duplicates `IsTicketOwner` for retrieve/update/destroy: filtering the queryset to the requesting user's own tickets makes those rows the only rows `get_object()` can ever return, so `IsTicketOwner` continues to apply defense-in-depth rather than being the sole enforcement point.

If assignment is added to this model later (e.g. an `assigned_agent` foreign key), the staff case should be reinstated as an explicit `Q(owner=self.request.user) | Q(assigned_agent=self.request.user)` filter - never a blanket `is_staff` bypass - so list results stay scoped to exactly the rows the policy grants that agent, not every customer's ticket.
