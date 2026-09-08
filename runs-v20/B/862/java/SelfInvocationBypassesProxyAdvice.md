## Verdict

Confirmed, fix applied. CWE-862 (Missing Authorization) at `InvoiceService.java:33`.

## Source

`MaintenanceController.runMonthEndCleanup()` (`POST /api/maintenance/month-end-cleanup`) is reachable by any authenticated user - the comment on the endpoint states it "only requires a valid session" and relies on the assumption that only the nightly batch job will call it. That is not an enforced control. The controller calls `invoiceService.processMonthEndCleanup()`, which loops over voided invoices and calls `deleteInvoice(invoice.getId())` on line 33 via `this` (self-invocation, same bean, same class).

## Fix

### File: InvoiceService.java
```java
package com.example.billing.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.example.billing.model.Invoice;
import com.example.billing.repository.InvoiceRepository;

@Service
public class InvoiceService {

    private final InvoiceRepository invoiceRepository;
    private final InvoiceDeletionService invoiceDeletionService;

    public InvoiceService(InvoiceRepository invoiceRepository, InvoiceDeletionService invoiceDeletionService) {
        this.invoiceRepository = invoiceRepository;
        this.invoiceDeletionService = invoiceDeletionService;
    }

    public void deleteInvoice(Long id) {
        invoiceDeletionService.deleteInvoice(id);
    }

    /**
     * Nightly batch job entry point: purges invoices that were voided
     * during the billing cycle and never finalized.
     */
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            invoiceDeletionService.deleteInvoice(invoice.getId());
        }
    }
}
```

### File: InvoiceDeletionService.java
```java
package com.example.billing.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.example.billing.repository.InvoiceRepository;

/**
 * Holds the authorization-checked delete operation on its own bean so every
 * caller - including other methods on InvoiceService - invokes it through
 * the Spring AOP proxy. Method security cannot intercept a same-class
 * (self-invocation) call, which is why this check does not live on
 * InvoiceService itself.
 */
@Service
public class InvoiceDeletionService {

    private final InvoiceRepository invoiceRepository;

    public InvoiceDeletionService(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteInvoice(Long id) {
        invoiceRepository.deleteById(id);
    }
}
```

## Explanation

Spring method security (`@PreAuthorize`) is enforced by an AOP proxy wrapped around the bean. A call made through the proxy - from a controller, from another bean - passes through the interceptor that evaluates `hasRole('ADMIN')`. A call made on `this` from inside the same class never reaches the proxy at all, so the annotation on `deleteInvoice` is silently skipped for exactly the call at line 33. Because the calling endpoint enforces nothing beyond "has a valid session," any authenticated user - not just an admin - can hit `/api/maintenance/month-end-cleanup` and delete every voided invoice with no role check ever evaluated.

The fix moves the annotated operation onto a separate bean, `InvoiceDeletionService`. `InvoiceService.processMonthEndCleanup()` now calls `invoiceDeletionService.deleteInvoice(...)` instead of `this.deleteInvoice(...)`, which is a call through the real Spring proxy, so `@PreAuthorize("hasRole('ADMIN')")` is genuinely evaluated against the authenticated caller from the HTTP request. `InvoiceService.deleteInvoice(Long id)` is kept as a thin delegate to the new bean so any other existing caller of that method keeps the same signature and behavior, now correctly enforced as well. No role or permission was added, changed, or removed - the pre-existing `hasRole('ADMIN')` requirement is simply made to actually run for this call path.

Verification: extracted both files to a scratch directory (outside the codebase) and compiled with `javac` (JDK 26) without the Spring/repository classpath available. The only diagnostics were "package/class does not exist" for `org.springframework.*`, `com.example.billing.model.Invoice`, and `com.example.billing.repository.InvoiceRepository` - all pre-existing external dependencies not part of this fix, already referenced identically in the original file. No syntax errors, and `InvoiceService`'s reference to the new same-package `InvoiceDeletionService` resolved cleanly with no "cannot find symbol" error, confirming the cross-file wiring is correct. `PreAuthorize`, `Service`, and `InvoiceRepository` are the same imports the original file already used; no new external name was introduced.

## Behaviour changes

- Before the fix: any authenticated user (regardless of role) hitting `POST /api/maintenance/month-end-cleanup` could delete all voided invoices, with the `hasRole('ADMIN')` check never evaluated.
- After the fix: the same endpoint now enforces `hasRole('ADMIN')` on the actual delete operation. An authenticated non-admin caller now receives an authorization denial (translated to HTTP 403 by Spring Security's `ExceptionTranslationFilter`, since the call happens inside the HTTP request/filter chain) instead of having the deletion silently performed. This is the intended effect of closing the finding, not a side effect - legitimate admin callers and the intended nightly-batch use case (assuming it is invoked by, or on behalf of, an admin-authenticated principal) are unaffected.
- No new permission, role, or ownership rule was introduced; no other method's behavior changed.
