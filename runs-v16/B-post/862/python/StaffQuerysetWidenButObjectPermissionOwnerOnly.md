# CWE-862: Missing Authorization

## Verdict

Exploitable. Any authenticated user with the `is_staff` flag can list all tickets in the system, including customers' private message bodies, regardless of ownership or assignment.

## Source

The authorization decision is the `is_staff` attribute on the request user. The source is the unauthenticated attacker gaining staff credentials or an internal staff account performing unauthorized data exfiltration.

## Fix

**Vulnerable code (line 29-33):**
```python
def get_queryset(self):
    if self.request.user.is_staff:
        # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return Ticket.objects.all()
    return Ticket.objects.filter(owner=self.request.user)
```

**Fixed code:**
```python
def get_queryset(self):
    return Ticket.objects.filter(owner=self.request.user)
```

## Explanation

The vulnerability occurs because `get_queryset()` returns all tickets for any staff member without checking ownership. While `IsTicketOwner.has_object_permission()` enforces ownership for retrieve/update/delete operations, it never runs for list operations—DRF's generic views skip per-instance permission checks on collections. The queryset itself is the only gate for list endpoints, so the widened queryset for staff members bypasses the ownership requirement entirely. Any staff account can enumerate and read all customers' ticket bodies, violating the stated policy that tickets are visible only to the owner and the explicitly assigned agent. The fix removes the staff exception and scopes the queryset to the requesting user's own tickets in all cases, ensuring the ownership constraint from `IsTicketOwner` is respected whether the view is called for a list or a detail operation.

## Behaviour changes

The fix changes which tickets a staff member can retrieve:

- **Before**: Staff members retrieve all tickets in the system via list operations; detail operations (retrieve/update/delete) are constrained by `IsTicketOwner.has_object_permission()`.
- **After**: Staff members retrieve only their own tickets in all operations (list and detail), consistent with the stated product policy.

This is an intentional narrowing of access rights. If a different policy is intended—such as allowing designated support staff to view assigned tickets while keeping admin staff separate—that requires a custom permission class implementing the per-user assignment relationship, not a blanket `is_staff` check in `get_queryset()`.
