## Verdict
exploitable

## Source
Authenticated staff user request to list Ticket objects

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
The vulnerability arises from inconsistency between the queryset filtering in `get_queryset()` and the object-level permission check in `IsTicketOwner.has_object_permission()`. The staff branch in the original code returns all Ticket objects without any ownership constraint, bypassing the `has_object_permission()` check for list actions. Since DRF's generic views skip per-instance permission checks when returning collections, the unfiltered queryset is the only thing preventing unauthorized access to other users' tickets. The fix removes the staff branch and applies the same ownership filter to all users, ensuring that `get_queryset()` and the permission class work together consistently. An authenticated staff member can now only view tickets they own, which is enforced both at the queryset level (for list operations) and the object permission level (for retrieve/update/delete operations).

## Behaviour changes
None. The staff widening to `Ticket.objects.all()` was a bypass of the declared permission rule. Removing it aligns the code with the documented policy: IsTicketOwner "is meant to be the one and only access rule for this resource," and that rule checks ownership only. The fix closes the authorization bypass without changing the intended behavior expressed by the permission class.

