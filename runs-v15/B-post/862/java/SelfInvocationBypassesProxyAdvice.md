## Verdict

**CWE-862: Missing Authorization** — Confirmed. The `processMonthEndCleanup()` method lacks authorization checks and invokes `deleteInvoice()` via `this`, bypassing Spring Security's proxy-based method-level advice. An unauthenticated or unprivileged caller with access to trigger the batch job can delete restricted invoices.

## Source

**InvoiceService.java, line 29–35:**

```java
public void processMonthEndCleanup() {
    List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
    for (Invoice invoice : voidedInvoices) {
        deleteInvoice(invoice.getId());
    }
}
```

**Root cause:** `processMonthEndCleanup()` is a public method with no `@PreAuthorize` annotation. When it calls `deleteInvoice(invoice.getId())` on `this`, the call bypasses the Spring Security proxy and directly invokes the target method's implementation, ignoring the `@PreAuthorize("hasRole('ADMIN')")` guard on `deleteInvoice()`.

## Fix

Add `@PreAuthorize("hasRole('ADMIN')")` to the `processMonthEndCleanup()` method signature:

```java
@PreAuthorize("hasRole('ADMIN')")
public void processMonthEndCleanup() {
    List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
    for (Invoice invoice : voidedInvoices) {
        deleteInvoice(invoice.getId());
    }
}
```

## Explanation

Spring Security's method-level authorization (`@PreAuthorize`) is enforced via a proxy that wraps the bean. When a method calls another method on `this`, the call bypasses the proxy and directly invokes the implementation, so the guard is not evaluated.

The `processMonthEndCleanup()` method is the entry point for a nightly batch job; it must have its own authorization check to ensure only an ADMIN-role caller can initiate the cleanup. Once the authorization check passes, the internal call to `deleteInvoice()` is permitted (the check at that site validates the action itself, should it be called directly by a user). Method-level authorization is layered: both the entry point and the sensitive operation are guarded independently, so every code path is covered.

Alternatively, extract `deleteInvoice()` into a separate `InvoiceDeleteService` bean and inject it into `InvoiceService`. Then call `invoiceDeleteService.deleteInvoice()` instead of `this.deleteInvoice()`. The injected bean is a proxy, so the authorization advice applies. This approach is preferable for production code where the deletion logic is reused across multiple classes.

## Behaviour changes

**Before fix:**
- An unauthenticated user or a caller without `ROLE_ADMIN` can invoke `processMonthEndCleanup()` if the method is exposed as an endpoint (HTTP mapping) or called via a scheduler without authentication context. Voided invoices are deleted without authorization check.
- Authorization context is lost when `deleteInvoice()` is invoked on `this`.

**After fix:**
- `processMonthEndCleanup()` checks that the caller holds `ROLE_ADMIN` before proceeding. If the check fails, Spring Security raises `AccessDeniedException`, which is translated to a 403 Forbidden response by `ExceptionTranslationFilter`.
- Both the entry point (`processMonthEndCleanup`) and the sensitive operation (`deleteInvoice`) are guarded by authorization advice, providing defence in depth.
