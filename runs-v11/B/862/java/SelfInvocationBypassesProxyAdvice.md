## Verdict

Real issue confirmed. The `processMonthEndCleanup()` method invokes the protected `deleteInvoice()` method on `this`, which bypasses Spring's method security proxy and its `@PreAuthorize` enforcement. Any caller can trigger invoice deletion without authorization checks.

## Source

`processMonthEndCleanup()` at line 29–35 performs sensitive deletion operations by calling `deleteInvoice()` at line 33 on `this`. The `deleteInvoice()` method is protected with `@PreAuthorize("hasRole('ADMIN')")`, but self-invocation on `this` does not route through the proxy and therefore bypasses the authorization advice entirely.

Call chain: `processMonthEndCleanup()` → `this.deleteInvoice()` (no proxy interception) → `invoiceRepository.deleteById()`.

## Fix

Inject the service into itself and replace the self-invocation with a call through the proxy:

```java
package com.example.billing.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.example.billing.model.Invoice;
import com.example.billing.repository.InvoiceRepository;

@Service
public class InvoiceService {

    private final InvoiceRepository invoiceRepository;
    private InvoiceService self;

    public InvoiceService(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    @Autowired
    public void setSelf(InvoiceService self) {
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

The changes are:
- Add a `private InvoiceService self` field to hold the proxy instance.
- Add a `@Autowired` setter `setSelf(InvoiceService self)` that Spring uses to inject the bean's proxy after construction.
- Replace `this.deleteInvoice()` with `self.deleteInvoice()` at line 33, ensuring the call routes through the proxy and triggers `@PreAuthorize` enforcement.

## Explanation

Spring's method security is proxy-based: when a method bears `@PreAuthorize`, Spring wraps the bean with a proxy that intercepts external calls and checks authorization before allowing the method to execute. However, when a method calls another method on `this`, the call bypasses the proxy and executes directly on the target object.

By injecting the service into itself, `self` holds a reference to the proxy rather than the target. Calling `self.deleteInvoice()` routes through the proxy, where `@PreAuthorize("hasRole('ADMIN')")` is evaluated. If the caller lacks the `ADMIN` role, `@PreAuthorize` raises `AccessDeniedException` and the deletion is blocked. Since `processMonthEndCleanup()` runs as a scheduled job outside HTTP context, it must either run with a security context that grants admin privileges or handle the exception at the job's invocation point.

The Java guidance states: "Method security is proxy-based, so a call the bean makes to itself on `this` bypasses the advice entirely… move the annotated method onto a collaborating bean rather than annotating a method its own class calls." This fix uses the proxy-injection variant of that guidance.

## Behaviour changes

- `processMonthEndCleanup()` no longer silently performs deletions regardless of caller role. Calls to `self.deleteInvoice()` now enforce the same `@PreAuthorize` gate that protects direct calls to the method.
- If the scheduled job runs without an `ADMIN` principal in the security context, `AccessDeniedException` is raised. The job's invoker must set up the appropriate security context (e.g., a system principal with admin role, or a specific user context with admin authority) to allow the batch cleanup to proceed.
- The authorization check is centralized at `deleteInvoice()`, so all callers—whether scheduled jobs or HTTP endpoints—are subject to the same rule. This eliminates the proxy-bypass hole.
