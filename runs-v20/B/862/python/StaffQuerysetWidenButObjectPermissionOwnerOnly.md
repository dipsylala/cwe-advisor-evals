## Verdict

Exploitable. CWE-862 (Missing Authorization), high confidence.

## Source

`self.request.user` (the authenticated caller) and its `is_staff` flag, evaluated in `TicketViewSet.get_queryset()` at `views.py:29-32`.

## Fix

`TicketViewSet.get_queryset()` (`views.py:29-32`) is the sink: for a list request from any `is_staff` account, it returns `Ticket.objects.all()` - every customer's ticket, including the raw message body the class docstring says is sensitive - instead of the owner-scoped queryset the else branch uses.

Sink contract before the fix:
- **Returns** - a `QuerySet[Ticket]` that DRF's `ListModelMixin.list()` paginates and serializes directly, and that `GenericAPIView.get_object()` filters by lookup field for retrieve/update/destroy.
- **Discards** - nothing; the widened queryset is used as-is.
- **Arguments left implicit** - none; the widening is an unconditional branch on `is_staff`, not a parameter.
- **Failure behaviour** - none; the call cannot fail, it can only return the wrong scope.

`IsTicketOwner.has_object_permission()` (not in this file) is only invoked by `self.get_object()`, i.e. on retrieve/update/destroy - never on `list()`. So for the list action, `get_queryset()` is the only authorization check that exists, and the `is_staff` branch bypasses it entirely: any staff account, of any role, can list every customer's ticket regardless of assignment. The docstring states `IsTicketOwner` is meant to be the resource's one and only access rule, and that assignment-based staff access is handled by a separate endpoint not modeled here - so the widening is not a narrower version of an intended staff capability, it is a copy-paste of a pattern from `AdminAuditLogViewSet` that does not apply to this resource.

The fix removes the `is_staff` branch and always scopes the queryset to the requesting user's own tickets, matching Key Principle 19 in `cwe/862/python/INDEX.md` ("Scope `get_queryset()` to the requesting user ... filtering the queryset is the only thing standing between a collection endpoint and other people's rows") and Key Principle 17 ("Watch the staff branch: where `get_queryset()` widens for staff but `has_object_permission()` compares owner IDs alone, the two disagree and the wider queryset is the one that decided which rows exist").

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

    get_queryset() no longer widens for is_staff: IsTicketOwner's
    has_object_permission() only runs from self.get_object() (retrieve/
    update/destroy), so it never constrained what the list action
    returned, and the widened queryset was the one actually deciding
    which rows staff could see. Scoping the queryset to the owner makes
    list consistent with the object-level check.
    """

    serializer_class = None
    permission_classes = [IsAuthenticated, IsTicketOwner]

    def get_queryset(self):
        return Ticket.objects.filter(owner=self.request.user)
```

## Explanation

The `is_staff` branch in `get_queryset()` returned `Ticket.objects.all()` for any staff account on the list action, and `IsTicketOwner.has_object_permission()` - the resource's only stated access rule - never runs for `list()`, so nothing else stood between that branch and every customer's ticket body. Removing the branch and always filtering by `owner=self.request.user` makes the list action enforce the same ownership rule the object-level permission enforces on retrieve/update/destroy, closing the gap the SAST finding identifies. Assignment-based staff access, per the docstring, goes through a separate endpoint not modeled in this file, so it is intentionally not reintroduced here.

## Behaviour changes

- Staff accounts (`is_staff=True`) now see only their own tickets from the list endpoint, the same as any other authenticated user, instead of every ticket in the system. This is the intended effect of the fix, not a side effect: the docstring states ownership is meant to be the resource's sole access rule, and the removed branch was an accidental widening copied from an unrelated viewset.
- No change to retrieve, update, delete, create, serialization, or response status/format - `has_object_permission()` and `IsTicketOwner` are unmodified, and the else-branch scoping logic is unchanged, only made unconditional.
- Staff-assisted ticket access via assignment is out of scope for this fix: the docstring says it is implemented through a separate endpoint not present in this file, so no assignment-based queryset widening was added here.

**Verification**: `python -m py_compile` on the fixed file (copied to a scratch directory outside the repo) succeeded with no errors. No new imports, names, or APIs were introduced - the fix only removes the `if self.request.user.is_staff:` branch and its `return Ticket.objects.all()`, using names (`Ticket`, `self.request.user`, `.filter`, `owner=`) already present in the original file.
