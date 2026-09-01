## Verdict

**CWE-862: Missing Authorization** — Confirmed

The `retrieve()` method in `InvoiceViewSet` bypasses object-level authorization checks by directly fetching the Invoice using `get_object_or_404(Invoice, pk=pk)` instead of routing through Django REST Framework's standard `get_object()` method. This allows any authenticated user to access invoices they do not own, bypassing both the `get_queryset()` filtering and the `IsInvoiceOwner` permission class.

## Source

The vulnerability originates from the `pk` URL parameter in the `retrieve()` method signature (line 19), which is attacker-controlled via the request URL.

```python
def retrieve(self, request, pk=None):
```

An authenticated attacker can supply any invoice ID as the `pk` value to access invoices they do not own.

## Fix

Replace the direct `get_object_or_404()` call with DRF's standard `self.get_object()` method, which automatically applies both queryset filtering and object-level permission checks:

**Vulnerable code (line 21):**
```python
invoice = get_object_or_404(Invoice, pk=pk)
```

**Fixed code:**
```python
invoice = self.get_object()
```

Additionally, remove the now-unused import:
```python
# Remove this line (no longer needed)
from django.shortcuts import get_object_or_404
```

The complete fixed method:
```python
def retrieve(self, request, pk=None):
    invoice = self.get_object()
    return Response({
        "id": invoice.id,
        "owner_id": invoice.owner_id,
        "total_cents": invoice.total_cents
    })
```

## Explanation

The `InvoiceViewSet` defines `permission_classes = [IsAuthenticated, IsInvoiceOwner]` and a properly scoped `get_queryset()` that filters invoices by owner. However, the custom `retrieve()` method circumvents this protection by using `get_object_or_404()` directly, which fetches any invoice by ID without applying the `get_queryset()` scoping or calling `IsInvoiceOwner.has_object_permission()`.

Django REST Framework's `self.get_object()` is the standard method for object retrieval in viewsets precisely because it:
1. Applies the `get_queryset()` filtering, which restricts non-staff users to their own invoices
2. Calls `check_object_permissions()` to enforce the `IsInvoiceOwner.has_object_permission()` check
3. Returns a 404 (not a 403) when the user doesn't own the object, preventing enumeration of invoice IDs

Using `self.get_object()` restores the authorization enforcement that the viewset's configuration already declares but the custom method was bypassing.

## Behaviour changes

| Aspect | Before | After |
|--------|--------|-------|
| **Access to owned invoice** | 200 OK | 200 OK (unchanged) |
| **Access to unowned invoice by non-staff user** | 200 OK with invoice data (vulnerability) | 404 Not Found (fixed) |
| **Access by staff user** | 200 OK (any invoice) | 200 OK (unchanged, queryset returns all due to `is_staff` check) |
| **Inactive permission check** | `IsInvoiceOwner.has_object_permission()` never called | Now called for all requests |
| **Attack surface** | Full invoice enumeration for authenticated users | Restricted to owned invoices only |
