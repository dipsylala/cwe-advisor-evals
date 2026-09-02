## Verdict

Exploitable. CWE-862 (Missing Authorization), confidence: high.

- Location: `views.py`, line 21 (sink), in `InvoiceViewSet.retrieve`.
- Source: the `pk` path parameter on the `retrieve` route, fully attacker-controlled by any authenticated user.
- Sink: `get_object_or_404(Invoice, pk=pk)`.

## Source

`InvoiceViewSet` defines `get_queryset()` to scope results to the requesting user's own invoices (all invoices for staff), and lists `IsInvoiceOwner` in `permission_classes` to enforce object-level ownership. Both mechanisms are bypassed by the overridden `retrieve()`:

- `retrieve()` calls `get_object_or_404(Invoice, pk=pk)` directly against the unfiltered `Invoice` manager, instead of `self.get_object()`. This ignores `get_queryset()`'s owner scoping entirely, so the lookup is not constrained to rows the caller owns.
- Because `has_object_permission()` on a DRF permission class only runs when something calls `self.get_object()` / `self.check_object_permissions()`, and neither is invoked here, `IsInvoiceOwner.has_object_permission()` never executes for this action. `permission_classes` still gates *that a user is authenticated* (`has_permission()` succeeds), but the object-level ownership check is silently skipped.

Net effect: any authenticated user can supply an arbitrary `pk` and retrieve any other user's invoice, including `total_cents`, regardless of ownership or staff status.

## Fix

Vulnerable code (`views.py`):

```python
def retrieve(self, request, pk=None):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    invoice = get_object_or_404(Invoice, pk=pk)
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

Fixed code:

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .models import Invoice
from .permissions import IsInvoiceOwner


class InvoiceViewSet(ModelViewSet):
    serializer_class = None
    permission_classes = [IsAuthenticated, IsInvoiceOwner]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Invoice.objects.all()
        return Invoice.objects.filter(owner_id=self.request.user.id)

    def retrieve(self, request, pk=None):
        invoice = self.get_object()
        return Response({
            "id": invoice.id,
            "owner_id": invoice.owner_id,
            "total_cents": invoice.total_cents
        })
```

(The `from django.shortcuts import get_object_or_404` import is dropped since it is no longer used anywhere in the file after this change.)

## Explanation

`self.get_object()` is DRF's standard object-fetch path: it looks the record up through `self.get_queryset()` (so a non-staff caller's lookup is already scoped to `owner_id=self.request.user.id`) and then calls `self.check_object_permissions(request, obj)`, which runs `IsInvoiceOwner.has_object_permission()` against the fetched object. Replacing the direct `get_object_or_404(Invoice, pk=pk)` call with `self.get_object()` restores both layers of defense that the custom `retrieve()` had bypassed: an invoice belonging to another (non-staff) user no longer matches the scoped queryset at all, so the lookup fails before any permission check even runs, and it fails with the same `Http404` that a nonexistent `pk` produces - a caller cannot distinguish "not yours" from "does not exist," which avoids turning `pk` into an enumeration oracle. Staff continue to see every invoice because `get_queryset()` already widens for `is_staff`, matching `IsInvoiceOwner.has_object_permission()`'s own staff allowance, so the two checks agree.

## Behaviour changes

- Requesting an invoice owned by a different, non-staff user: was `200` with the invoice's `id`, `owner_id`, and `total_cents` exposed; now `404`, identical in status and body shape to requesting a nonexistent `pk`. This is the fix - closing the missing-authorization gap - not an unrelated change.
- Requesting your own invoice, or any invoice as staff: unchanged, `200` with the same three fields.
- Requesting a nonexistent `pk`: unchanged, `404` (both `get_object_or_404` and `self.get_object()` raise `Http404` on no match).
- The now-unused `get_object_or_404` import is removed; this has no runtime behavior effect, it is cleanup made necessary by the fix itself.

No other behavior changes. The fix preserves the sink's original contract (return the invoice or a 404) while closing the authorization gap; the only case whose response changes is the one that was the vulnerability.
