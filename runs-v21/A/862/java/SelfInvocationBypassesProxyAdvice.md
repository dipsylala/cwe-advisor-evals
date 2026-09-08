## Verdict

CONFIRMED — CWE-862 missing authorization.

## Source

The `processMonthEndCleanup()` method (lines 29-35) lacks authorization checks. When it calls `deleteInvoice()` at line 33, the call is a self-invocation that bypasses Spring's AOP proxy, circumventing the `@PreAuthorize("hasRole('ADMIN')")` check on the target method. Any authenticated user reaching the endpoint in `MaintenanceController` can thus delete invoices without holding the ADMIN role.

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

The fix adds `@PreAuthorize("hasRole('ADMIN')")` to `processMonthEndCleanup()`, ensuring that only users with the ADMIN role can invoke this method. This guards the entry point to the batch job, closing the self-invocation bypass. The annotation is now enforced by Spring's AOP proxy at the boundary where the method is called from `MaintenanceController`, preventing unauthorized access before the method body executes and calls `deleteInvoice()`.
