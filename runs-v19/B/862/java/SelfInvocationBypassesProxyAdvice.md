## Verdict

**CONFIRMED: Missing Authorization.** The `processMonthEndCleanup()` method is a public entry point that performs sensitive operations (deleting invoices) without any authorization check. Although it internally calls `deleteInvoice()` which is protected by `@PreAuthorize("hasRole('ADMIN')")`, the call from within the same class bypasses Spring's proxy-based security advice entirely, leaving the public `processMonthEndCleanup()` method unprotected.

## Source

The vulnerable method is the public `processMonthEndCleanup()` on line 29. It is accessible to any authenticated or unauthenticated caller and iterates through voided invoices, calling the authorization-protected `deleteInvoice()` method from within itself (line 33). This self-invocation bypasses the `@PreAuthorize` annotation on `deleteInvoice()`.

## Fix

Add `@PreAuthorize("hasRole('ADMIN')")` to the `processMonthEndCleanup()` method to enforce the same authorization requirement at the entry point. This ensures that only ADMIN users can invoke this batch operation, and any unprivileged caller is denied before the sensitive action occurs.

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

Per CWE-862 guidance, every sensitive action must have an explicit authorization check applied through the same centralized mechanism used elsewhere in the application. This method performs a sensitive operation (batch deletion of invoices) and must not be callable by unprivileged users.

The vulnerability occurs because Spring's method-level security uses proxy-based advice. When a method calls another method on the same class instance (`this`), the call bypasses the proxy and its security annotations. By annotating `processMonthEndCleanup()` itself with `@PreAuthorize("hasRole('ADMIN')")`, the authorization check is enforced at the entry point, and the subsequent internal call to `deleteInvoice()` remains protected as a defense-in-depth measure.

The fix applies the same authorization requirement (`hasRole('ADMIN')`) that is already used on the `deleteInvoice()` method, maintaining consistency with comparable protected operations in the application.

## Behaviour changes

- `processMonthEndCleanup()` now requires the ADMIN role to be invoked by any caller.
- An unauthenticated or non-ADMIN caller who attempts to invoke this method will receive an `AccessDeniedException` (translated to HTTP 403 in a web context, or an exception in a batch job context).
- If this method is invoked by a scheduled batch job, the job scheduler must be running with ADMIN-level credentials, or the job must catch and handle `AccessDeniedException` appropriately.
- The method's behavior for authorized callers remains identical.
