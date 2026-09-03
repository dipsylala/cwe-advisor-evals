## Verdict
**Vulnerable.** Line 32 returns all tickets for any staff user, bypassing the intended per-object authorization enforced by `IsTicketOwner`.

## Source
```python
def get_queryset(self):
    if self.request.user.is_staff:
        return Ticket.objects.all()  # Line 32 - grants unrestricted access
    return Ticket.objects.filter(owner=self.request.user)
```

The docstring states the access policy: "visible only to the customer who filed it, plus whichever single agent it has been explicitly assigned to." `IsTicketOwner.has_object_permission()` enforces this on detail actions (retrieve/update/destroy), but `get_queryset()` controls what the list action returns—and `has_object_permission()` is never called for list actions, making the queryset filter the only enforcement point.

## Fix
```python
from django.db.models import Q

def get_queryset(self):
    return Ticket.objects.filter(
        Q(owner=self.request.user) | Q(assigned_to=self.request.user)
    )
```

Apply the same authorization logic to all users. A ticket is visible only when the current user is the owner or the assigned agent. Remove the `is_staff` branch entirely—staff roles do not grant blanket access.

## Explanation
The vulnerability occurs because `get_queryset()` bypasses object-level authorization for staff users. Django REST Framework's `has_object_permission()` checks are applied only during detail actions (retrieve, update, destroy), never during list. The queryset returned by `get_queryset()` is the only guard for list, and is also pre-filtered for detail actions (it would be inefficient to load all rows and filter in memory).

The docstring correctly identifies the product policy: authorization is per-ticket, keyed to ownership or assignment, not role. The fix applies that same filter uniformly, ensuring that a user (staff or otherwise) sees only tickets they own or are assigned to handle. This makes the authorization consistent across all actions and aligns the queryset filtering with the stated access policy.
