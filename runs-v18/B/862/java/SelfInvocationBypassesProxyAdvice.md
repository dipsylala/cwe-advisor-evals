## Verdict

CONFIRMED. The finding is valid. The vulnerability is exploitable: any authenticated non-admin user can invoke the maintenance endpoint and bypass the `@PreAuthorize("hasRole('ADMIN')')` check on `deleteInvoice()` by triggering a self-invocation call within the same Spring bean instance, which bypasses Spring Security's proxy-based method interception.

## Source

Entry point: `MaintenanceController.runMonthEndCleanup()` (accessible to any authenticated user via POST `/api/maintenance/month-end-cleanup`)

Call chain:
1. `MaintenanceController.runMonthEndCleanup()` - no authorization check
2. → `InvoiceService.processMonthEndCleanup()` (line 29) - no authorization check
3. → `InvoiceService.deleteInvoice()` (line 33, via `this.deleteInvoice()`) - has `@PreAuthorize("hasRole('ADMIN')")` but bypassed by self-invocation

Sink: Line 33 in `InvoiceService.java`, where `deleteInvoice()` is called on `this` without authorization validation.

## Fix

### File: InvoiceService.java

```java
package com.example.billing.service;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.example.billing.model.Invoice;
import com.example.billing.repository.InvoiceRepository;

@Service
public class InvoiceService {

    private final InvoiceRepository invoiceRepository;

    public InvoiceService(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteInvoice(Long id) {
        invoiceRepository.deleteById(id);
    }

    /**
     * Nightly batch job entry point: purges invoices that were voided
     * during the billing cycle and never finalized.
     */
    @PreAuthorize("hasRole('ADMIN')")
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            deleteInvoice(invoice.getId());
        }
    }
}
```

## Explanation

The vulnerability is a **self-invocation bypass of method security**. Spring Security enforces method-level authorization via a proxy-based advice mechanism: when a method annotated with `@PreAuthorize` is called through the bean's proxy (e.g., via dependency injection or through another bean), the authorization check runs. However, when a method calls another method on `this` (the same instance), the call bypasses the proxy entirely and goes directly to the target method, so the `@PreAuthorize` advice is never invoked.

In this case:
- `processMonthEndCleanup()` has no authorization check
- Any authenticated user (non-admin) can call `MaintenanceController.runMonthEndCleanup()`, which is the entry point
- `processMonthEndCleanup()` then calls `this.deleteInvoice()` on itself
- Even though `deleteInvoice()` has `@PreAuthorize("hasRole('ADMIN')')`, the self-invocation bypasses Spring's proxy and the check never runs
- Result: an unprivileged user can delete invoices

**The fix**: Add `@PreAuthorize("hasRole('ADMIN')')` to `processMonthEndCleanup()` (line 29). This ensures the authorization check runs at the entry point before any code inside the method executes. Since the method itself calls `deleteInvoice()` which requires ADMIN role, the entire method must be protected with the same requirement. With this annotation in place, Spring's proxy will intercept any external call to `processMonthEndCleanup()` and verify the caller has the ADMIN role before allowing execution.

The fix employs the centralized, method-level authorization mechanism already in use for `deleteInvoice()`, consistent with Spring Security best practices. It protects the entire call chain: any caller (whether direct, through the controller, or scheduled) must have the required role, and the authorization check happens at the proxy level where Spring can enforce it.

## Behaviour changes

**For authorized users (ADMIN role):**
- No change in behavior. ADMIN users can still call `MaintenanceController.runMonthEndCleanup()` and `processMonthEndCleanup()` will execute normally.

**For unauthorized users (non-ADMIN authenticated users):**
- **Before fix**: Request reaches `processMonthEndCleanup()` and allows deletion of voided invoices.
- **After fix**: Request is denied at the proxy boundary before `processMonthEndCleanup()` is entered. Spring's `ExceptionTranslationFilter` converts the `AccessDeniedException` into an HTTP 403 Forbidden response.

**For unauthenticated users:**
- No change. The global security filter chain already requires authentication at `MaintenanceController.runMonthEndCleanup()`, and the `@PreAuthorize` on the service method is for authenticated users only. Unauthenticated requests are still denied.

**External call contract:**
- The signature and return type of `processMonthEndCleanup()` remain unchanged (public void method). Only callers that go through the Spring-managed bean proxy are affected; direct instantiation and calling (not typical in a Spring application) would not be subject to the authorization check.
