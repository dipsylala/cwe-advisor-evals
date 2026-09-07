## Verdict
CWE-862 (Missing Authorization) confirmed. The `processMonthEndCleanup()` method calls `deleteInvoice()` directly on the same instance, bypassing Spring's authorization proxy. The `@PreAuthorize("hasRole('ADMIN')")` annotation on `deleteInvoice()` does not execute.

## Source
- **File**: InvoiceService.java
- **Line**: 33
- **Call chain**: MaintenanceController.runMonthEndCleanup() → InvoiceService.processMonthEndCleanup() → InvoiceService.deleteInvoice() (line 33)
- **Root cause**: Self-invocation bypasses Spring AOP proxy, so authorization checks are not applied.

## Fix

### File: InvoiceService.java
```java
package com.example.billing.service;

import java.util.List;

import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.example.billing.model.Invoice;
import com.example.billing.repository.InvoiceRepository;

@Service
public class InvoiceService {

    private final InvoiceRepository invoiceRepository;
    private final InvoiceService self;

    public InvoiceService(InvoiceRepository invoiceRepository, @Lazy InvoiceService self) {
        this.invoiceRepository = invoiceRepository;
        this.self = self;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteInvoice(Long id) {
        invoiceRepository.deleteById(id);
    }

    /**
     * Nightly batch job entry point: purges invoices that were voided
     * during the billing cycle and never finalized.
     */
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            self.deleteInvoice(invoice.getId());
        }
    }
}
```

## Explanation
Spring's `@PreAuthorize` annotation is enforced by AOP proxies wrapping the bean. When a method calls another method on the same instance (self-invocation), the call bypasses the proxy and lands directly on the actual object, skipping authorization checks.

**Fix approach**: Inject a lazy proxy of the service into itself via `@Lazy` annotation. This breaks the circular dependency by deferring proxy instantiation. Now line 33 calls `self.deleteInvoice()` instead of `deleteInvoice()`, routing the call through the authorization proxy. The security check executes and only requests with the ADMIN role succeed.

**Why `@Lazy`**: The `@Lazy` annotation ensures the injected proxy is created after the bean itself is initialized, avoiding a circular dependency deadlock. It is idiomatic Spring for this pattern and requires no additional dependencies or complex logic.
