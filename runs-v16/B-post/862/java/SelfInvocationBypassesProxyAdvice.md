## Verdict

exploitable

## Source

- **Entry point**: `processMonthEndCleanup()` (line 29) — public method with no authorization check
- **Sink**: `deleteInvoice(invoice.getId())` (line 33) — calls a method protected by `@PreAuthorize("hasRole('ADMIN')")` but via self-invocation

## Fix

**Vulnerable code** (original InvoiceService):

```java
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
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            // Line 33: VULNERABLE — self-invocation bypasses proxy-based authorization
            deleteInvoice(invoice.getId());
        }
    }
}
```

**Fixed code** (new collaborating service + modified InvoiceService):

Create new `InvoiceDeleteService.java`:

```java
package com.example.billing.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.example.billing.repository.InvoiceRepository;

@Service
public class InvoiceDeleteService {

    private final InvoiceRepository invoiceRepository;

    public InvoiceDeleteService(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteInvoice(Long id) {
        invoiceRepository.deleteById(id);
    }
}
```

Modify `InvoiceService.java`:

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
    private final InvoiceDeleteService invoiceDeleteService;

    public InvoiceService(InvoiceRepository invoiceRepository,
                          InvoiceDeleteService invoiceDeleteService) {
        this.invoiceRepository = invoiceRepository;
        this.invoiceDeleteService = invoiceDeleteService;
    }

    /**
     * Nightly batch job entry point: purges invoices that were voided
     * during the billing cycle and never finalized.
     */
    @PreAuthorize("hasRole('ADMIN')")
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            // Line 33: Now calls through injected service proxy — @PreAuthorize enforced
            invoiceDeleteService.deleteInvoice(invoice.getId());
        }
    }
}
```

## Explanation

The vulnerability is a **self-invocation bypass of proxy-based method security**. The original `InvoiceService.deleteInvoice()` is protected by `@PreAuthorize("hasRole('ADMIN')")`, but when `processMonthEndCleanup()` calls it via `this.deleteInvoice()` on line 33, the call is not intercepted by Spring's proxy. Method security advice only applies to calls that pass through the proxy; internal calls to `this` bypass it entirely, leaving no authorization check in place.

The fix extracts `deleteInvoice()` to a separate collaborating service bean (`InvoiceDeleteService`). `InvoiceService` now injects and calls through that service's proxy, ensuring the `@PreAuthorize` annotation on the extracted method is enforced at line 33. Additionally, `processMonthEndCleanup()` itself is protected with `@PreAuthorize("hasRole('ADMIN')")` to secure the entry point, preventing unprivileged callers from triggering batch operations that would otherwise bypass authorization via the self-invocation path.

## Behaviour changes

- **Added dependency**: `InvoiceDeleteService` is injected into `InvoiceService` constructor; this introduces a new collaborating bean with the same `InvoiceRepository` dependency. No functional change to behavior; constructor signature changed but injection is transparent to callers.
- **Method relocation**: `deleteInvoice()` method moved from `InvoiceService` to `InvoiceDeleteService`. Callers that obtained a reference to `InvoiceService` directly and called `.deleteInvoice()` must now be updated to call `invoiceDeleteService.deleteInvoice()` or access it via a service locator/injection point. Internal call in `processMonthEndCleanup()` automatically resolved through injected proxy.
- **Authorization added to entry point**: `@PreAuthorize("hasRole('ADMIN')")` added to `processMonthEndCleanup()`. This prevents unprivileged authenticated users from triggering the batch job manually. If the method runs only as an automatic scheduled task with no user context (e.g., `@Scheduled`), the annotation will cause authorization checks to fail, and the job must run under a service account or with `@EnableMethodSecurity` configured to permit scheduled jobs; confirm scheduling context before deploying this fix.
