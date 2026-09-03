## Verdict

**Confirmed.** The `get_queryset()` method bypasses the `IsTicketOwner` authorization check for staff users by returning all tickets unconditionally. List actions in DRF skip `has_object_permission()`, so queryset scoping is the only access control. Any authenticated staff member can list all customer tickets regardless of assignment.

## Source

`evals/cases/862/python/StaffQuerysetWidenButObjectPermissionOwnerOnly/views.py`, line 32.

The `get_queryset()` method contains a staff branch that returns `Ticket.objects.all()` without verifying the user is authorized to access all tickets.

## Fix

Replace the `get_queryset()` method to scope results to only the tickets the user is authorized to see:

```python
def get_queryset(self):
    return Ticket.objects.filter(owner=self.request.user)
```

**If staff assignment is required**, extend the filter to include tickets assigned to the staff member (add this logic after confirming the assignment field name in the `Ticket` model):

```python
def get_queryset(self):
    user = self.request.user
    if user.is_staff:
        # Staff see only tickets assigned to them
        return Ticket.objects.filter(assigned_to=user)
    return Ticket.objects.filter(owner=user)
```

Remove the `is_staff` check that returned all tickets.

## Explanation

The vulnerability occurs because `get_queryset()` widens access for staff without enforcement of the `IsTicketOwner` authorization rule. In DRF's generic views, `has_object_permission()` runs only when `get_object()` is called (retrieve, update, destroy actions), not during list operations. The queryset returned by `get_queryset()` is the sole access control for list actions, so a queryset that returns all rows bypasses the permission class entirely.

The fix scopes `get_queryset()` to return only objects the user is authorized to access: tickets they own (for customers) or are assigned to (for staff). This ensures the list action respects the intended authorization before returning results.

The `IsTicketOwner` permission class will continue to enforce object-level checks on detail actions through `has_object_permission()`, but the queryset-level scoping closes the gap for list operations.

## Behaviour changes

- **Before**: A staff user calling `GET /tickets/` receives all tickets across all customers, regardless of whether they are assigned to handle those tickets.
- **After**: A staff user calling `GET /tickets/` receives only tickets they own as a customer, or (with extended fix) only tickets explicitly assigned to them. A non-staff user continues to see only their own tickets.
- **Detail actions unchanged**: Calls to retrieve/update/delete a specific ticket still run the full `IsTicketOwner` permission check via `has_object_permission()`.
