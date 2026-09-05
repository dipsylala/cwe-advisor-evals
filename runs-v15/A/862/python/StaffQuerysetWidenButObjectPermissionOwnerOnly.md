## Verdict
CONFIRMED: Missing authorization check in queryset filtering allows staff users to view all tickets regardless of ownership.

## Source
The vulnerability is in `get_queryset()` at line 32. When a user is staff, the method returns `Ticket.objects.all()` without any filtering, completely bypassing the `IsTicketOwner` permission check. Object-level permissions only apply to detail operations (retrieve/update/destroy), not to the list action which uses `get_queryset()`, so staff users can view every customer's ticket body.

## Fix
Remove the `is_staff` exception that widens the queryset to all tickets. Apply the same ownership filter to all users:

```python
def get_queryset(self):
    return Ticket.objects.filter(owner=self.request.user)
```

## Explanation
The `IsTicketOwner` permission class checks `obj.owner_id == request.user.id`, implementing the policy that tickets are visible only to their owner. However, this object-level permission only runs during retrieve/update/destroy operations (when `get_object()` is called), not during list actions which use `get_queryset()`.

The staff exception at line 30-32 returns all tickets for any staff user, creating an authorization bypass. This allows support agents, sales staff, or any staff member to list and view sensitive customer data (ticket bodies) they have no business seeing.

The fix ensures all users see only their own tickets in the queryset, making the access control consistent and preventing unauthorized disclosure of customer information to other staff members.
