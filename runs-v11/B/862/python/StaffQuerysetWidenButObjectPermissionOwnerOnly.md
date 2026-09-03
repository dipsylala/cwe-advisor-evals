## Verdict

VULNERABLE. Missing authorization on the list action: `get_queryset()` returns all tickets for any staff member, bypassing the object-level ownership check enforced by `IsTicketOwner`. Object-level permissions (`has_object_permission()`) do not run on list actions in DRF, only on detail operations, so the staff branch in `get_queryset()` is unconstrained.

## Source

**File**: `views.py`  
**Lines**: 29–33  
**Vulnerable code**: The `get_queryset()` method returns `Ticket.objects.all()` when `self.request.user.is_staff` is true.

```python
def get_queryset(self):
    if self.request.user.is_staff:
        # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return Ticket.objects.all()
    return Ticket.objects.filter(owner=self.request.user)
```

**Data flow**: 
- Source: `self.request.user.is_staff` (boolean flag set by Django authentication)
- Flow: If true, queryset returns all tickets without filtering
- Sink: The queryset is used by DRF's list view to generate the response
- Gap: `has_object_permission()` is not called on list actions, so `IsTicketOwner`'s ownership check never runs

## Fix

Remove the `is_staff` branch from `get_queryset()`. Always filter by ownership, regardless of user role.

**Fixed code**:

```python
def get_queryset(self):
    return Ticket.objects.filter(owner=self.request.user)
```

## Explanation

The docstring states that `IsTicketOwner` is meant to be "the one and only access rule," with tickets visible only to the customer who filed them or the agent explicitly assigned to the ticket. However, DRF's object-level permission check (`has_object_permission()`) runs only during detail operations (retrieve/update/destroy via `self.get_object()`), not on the list action.

By returning an unfiltered queryset in the `is_staff` branch, `get_queryset()` bypasses ownership filtering entirely for list requests from staff users. No amount of object-level permission logic can constrain which rows the list view returns, because the queryset is built before `has_object_permission()` is ever called.

The fix removes the staff exception and filters the queryset by ownership for all users, making the list action consistent with the object permission check on detail operations. This enforces the stated policy: only the customer (owner) who filed the ticket and the assigned agent can retrieve it, at every endpoint.

## Behaviour changes

- **List action** for staff users: Returns 404 for tickets not owned by the requesting user (scoped queryset returns empty), instead of returning all tickets.
- **Detail action** (retrieve/update/delete) for staff users: Still protected by `IsTicketOwner.has_object_permission()` (unchanged, since this fix does not modify permission classes).
- **Queryset filtering**: All users (staff or not) now follow the same ownership constraint via `filter(owner=self.request.user)`.
- **Authorization response codes**: List requests from staff now return empty results (404 for missing rows, per the scoped queryset), which correctly signals "not yours" without confirming row existence.
