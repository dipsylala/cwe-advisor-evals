## Verdict

CONFIRMED - Missing Authorization in list action. Staff users return all tickets via `get_queryset()` without ownership check. The `IsTicketOwner.has_object_permission()` check only runs for detail/update/delete actions via `self.get_object()`, not for list. Queryset filtering is the only authorization enforcement for list actions.

## Source

The product policy defines tickets as visible "only to the customer who filed it, plus whichever single agent it has been explicitly assigned to." The `IsTicketOwner` permission class implements this rule for detail/update/delete via `has_object_permission()`, comparing `obj.owner_id` to `request.user.id`. The vulnerability is in `get_queryset()` which widens access for `is_staff=True` without reconciling with `IsTicketOwner`'s ownership constraint.

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
        # Scope queryset to the requesting user's tickets only.
        # has_object_permission() does not run on list actions, so queryset
        # filtering is the sole authorization check here. All users (including
        # staff) must satisfy the ownership rule defined by IsTicketOwner.
        # Future: when assignment field is added, extend this to:
        #   Q(owner=self.request.user) | Q(assigned_agent=self.request.user)
        return Ticket.objects.filter(owner=self.request.user)
```

## Explanation

The fix removes the `is_staff` branch that returns all tickets. In Django REST Framework, `has_object_permission()` on a permission class only runs when `self.get_object()` is called - in retrieve, update, and destroy actions. The list action returns a queryset without applying per-object permission checks, so queryset filtering is the only authorization enforcement available for list results. The original code allowed staff to bypass this by returning `Ticket.objects.all()`, while `IsTicketOwner` enforced ownership only in detail/update/delete.

The fix scopes `get_queryset()` to tickets owned by the requesting user for all user types. This ensures the list action respects the same ownership rule that `IsTicketOwner.has_object_permission()` enforces on other actions. The comment notes that when an assignment field is modeled, the queryset can be extended to include tickets assigned to the user using a disjunctive filter.

## Behaviour changes

- Staff users can no longer list all customer tickets; they see only their own tickets
- Consistent authorization: all users now see tickets via the same ownership filter that `IsTicketOwner` enforces on detail/update/delete
- To restore a broader staff view (if intended), add an `assigned_agent` field to the Ticket model and extend the queryset to `Q(owner=user) | Q(assigned_agent=user)`
- List responses now return 200 with fewer rows; existing code querying the endpoint as staff will receive only their own tickets instead of all tickets
