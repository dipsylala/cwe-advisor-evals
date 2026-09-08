## Verdict

Confirmed. `processMonthEndCleanup()` deletes invoices through an internal, unguarded call path that never enforces the `ADMIN`-only check declared on `deleteInvoice()`.

## Source

`processMonthEndCleanup()` (line 29) is the entry point that reaches the sink. For each voided invoice it calls `deleteInvoice(invoice.getId())` (line 33) using an implicit `this` call. `deleteInvoice()` is annotated `@PreAuthorize("hasRole('ADMIN')")`, but Spring's method-security check is applied by a proxy wrapped around the bean at injection time, not by the target object itself. A call made from inside the same class (`this.deleteInvoice(...)`, or the bare `deleteInvoice(...)` written here) never passes back through that proxy, so the advice — including the authorization check — never runs. Any caller able to reach `processMonthEndCleanup()` therefore deletes invoices with no role check enforced at all, regardless of who or what triggers the cleanup.

## Fix

### File: InvoiceService.java
```java
package com.example.billing.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.example.billing.model.Invoice;
import com.example.billing.repository.InvoiceRepository;

@Service
public class InvoiceService {

    private final InvoiceRepository invoiceRepository;

    // Self-injected reference to this bean's Spring-managed proxy (not the
    // raw target). Routing internal calls through it, instead of an
    // implicit `this` call, makes them pass back through the same proxy
    // that external callers use, so @PreAuthorize is evaluated either way.
    // @Lazy defers resolution of this field until first use, which avoids
    // a circular-dependency failure while the bean is still being created.
    @Autowired
    @Lazy
    private InvoiceService self;

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
            self.deleteInvoice(invoice.getId());
        }
    }
}
```

## Explanation

Spring's default proxy-based method security (JDK dynamic proxies or CGLIB) wraps the bean instance handed out by the application context; `@PreAuthorize` is woven in as advice on that wrapper, not on the underlying object. Code running inside the target class that calls one of its own methods directly does not go through the wrapper, so any advice attached to that method — security checks, transactions, caching — is silently skipped. That is exactly what happened at line 33: `processMonthEndCleanup()` called `deleteInvoice()` as a same-class method call, so `hasRole('ADMIN')` never executed, and the deletion proceeded unconditionally for every voided invoice.

The fix keeps the authorization rule declared in exactly one place, on `deleteInvoice()`, and closes the bypass by making the internal caller go through the proxy instead of around it. `self` is a field that Spring populates with this bean's own proxy; because the bean cannot fully construct itself and inject its own proxy in the same step, `@Lazy` defers that injection until the field is first read, after the context has finished wiring the bean. Replacing `deleteInvoice(invoice.getId())` with `self.deleteInvoice(invoice.getId())` sends the call back out through the proxy, so `@PreAuthorize` runs for the batch path exactly as it does for any other caller of `deleteInvoice()`. No other file in the call chain needed a change, and no new sink or bypass was introduced — the existing authorization rule is simply no longer skippable via this call path.
