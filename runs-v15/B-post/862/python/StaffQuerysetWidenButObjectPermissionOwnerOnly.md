## Verdict

**CONFIRMED** - CWE-862 (Missing Authorization)

The `get_queryset()` method widens the queryset for staff members to return all tickets without applying resource-level authorization checks. The object-level permission `IsTicketOwner.has_object_permission()` only runs on retrieve/update/delete operations, not on list, leaving the list endpoint open to any authenticated staff member regardless of ticket ownership.

## Source

**File:** views.py  
**Line:** 32  
**Vulnerable Code:**
```python
def get_queryset(self):
    if self.request.user.is_staff:
        # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return Ticket.objects.all()  # <-- Line 32
    return Ticket.objects.filter(owner=self.request.user)
```

**Problem:** The staff branch returns all tickets in the system without any resource ownership or assignment check, bypassing the intended `IsTicketOwner` authorization. Since `has_object_permission()` is never invoked for list actions in DRF generic views, every staff member (regardless of role - support, sales, etc.) can enumerate and read all customer ticket bodies.

## Fix

Replace the staff branch in `get_queryset()` to scope the queryset by the requesting user, just as non-staff users are scoped:

```python
def get_queryset(self):
    # Scope to the requesting user for all users (staff and non-staff alike).
    # Authorization is consistent across all paths: a user sees only their own tickets.
    return Ticket.objects.filter(owner=self.request.user)
```

**Rationale:** The docstring states tickets are visible to the ticket owner and an assigned agent, but the model provides only the `owner` field. Until an `assigned_to` or similar field is added to the model, the only resource relationship that can be checked is ownership. This fix applies the same ownership filter to all users, ensuring list, retrieve, update, and delete operations all respect the same authorization boundary.

## Explanation

The vulnerability arises from a common pattern in Django REST Framework: a queryset that is widened for certain roles (staff) without corresponding narrowing of the object-level permission check. 

**How DRF permission checks work:**
- `has_permission(request, view)` - general endpoint access (applied to list and detail actions)
- `has_object_permission(request, view, obj)` - object-level access (applied only to retrieve, update, delete via `get_object()`)

The `IsTicketOwner` class implements only `has_object_permission()`, comparing `obj.owner_id` to `request.user.id`. For the list action, `get_object()` is never called, so `has_object_permission()` never runs. The result: the queryset filtering in `get_queryset()` is the only gate, and the staff branch removes that gate entirely.

**CWE-862 principle (from Python guidance line 19):**  
"Scope `get_queryset()` to the requesting user: generic views deliberately skip per-instance permission checks when returning a list, so filtering the queryset is the only thing standing between a collection endpoint and other people's rows."

Closing the vulnerability requires that `get_queryset()` apply the same ownership check to all users. This ensures that both list (where object permissions don't run) and detail (where they do) operations are gated by the same authorization rule.

## Behaviour changes

| Operation | Before | After |
|-----------|--------|-------|
| **List (non-staff user)** | Returns only own tickets | Returns only own tickets (unchanged) |
| **List (staff user)** | Returns ALL tickets in the system → **VULNERABILITY** | Returns only own tickets → **FIXED** |
| **Retrieve (non-staff, own ticket)** | 200 OK | 200 OK (unchanged) |
| **Retrieve (non-staff, other's ticket)** | 404 Not Found | 404 Not Found (unchanged) |
| **Retrieve (staff, own ticket)** | 200 OK | 200 OK (unchanged) |
| **Retrieve (staff, other's ticket)** | 200 OK (via `get_object()` + `IsTicketOwner`) | 404 Not Found (via scoped queryset) |

**Impact:** Staff members can no longer enumerate or access tickets they do not own. This closes the authorization bypass while maintaining a consistent permission model across all endpoints. To allow staff to view assigned tickets, add an `assigned_to` field to the Ticket model and extend the filter to `owner=self.request.user | assigned_to=self.request.user` (using `Q` objects).
