## Verdict

**Confirmed: Missing Authorization via Self-Invocation Bypass**

The method `processMonthEndCleanup()` performs sensitive deletion operations (invoking `deleteInvoice()`) without any authorization check. Although `deleteInvoice()` is protected by `@PreAuthorize("hasRole('ADMIN')")`, Spring's proxy-based method security is bypassed when a bean invokes a method on itself. Consequently, any authenticated user can trigger the endpoint `/api/maintenance/month-end-cleanup` and delete voided invoices intended only for administrators.

## Source

**Package:** `com.example.billing.service`  
**Class:** `InvoiceService`  
**Method:** `processMonthEndCleanup()` (line 29–35)  
**Sink:** Line 33 – `deleteInvoice(invoice.getId())`

**Call Chain:**
1. `MaintenanceController.runMonthEndCleanup()` (endpoint, no auth check)
2. `InvoiceService.processMonthEndCleanup()` (no auth check; self-invokes `deleteInvoice()`)
3. `InvoiceService.deleteInvoice()` (has `@PreAuthorize`, but bypassed by self-invocation)

**Root Cause:** The batch job method lacks an authorization check, and the Spring Security proxy that enforces `@PreAuthorize` on `deleteInvoice()` is not invoked for method calls within the same bean. This permits any authenticated user to trigger mass deletion.

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

The fix adds `@PreAuthorize("hasRole('ADMIN')")` to the `processMonthEndCleanup()` method. This establishes an authorization gate at the service layer where the sensitive action originates, rather than relying on the authorization check in the called method to protect against self-invocation bypass.

By protecting the entry point itself, the fix ensures that:
- Any caller—whether direct, through the HTTP endpoint, or via a background job—must hold the ADMIN role before the method executes
- The authorization is enforced through Spring's proxy before any deletion operations commence
- The annotation applies the same centralized authorization mechanism used by the sibling `deleteInvoice()` method

The `@PreAuthorize` annotation is the idiomatic Spring Security pattern for method-level role-based authorization and is evaluated by the runtime proxy each time the method is invoked from outside the bean. This closes the self-invocation bypass vector entirely.

## Behaviour changes

**Boundary Behavior:**
- **Before:** Any authenticated user (any role) could call `processMonthEndCleanup()` directly or via the `/api/maintenance/month-end-cleanup` endpoint and delete all voided invoices.
- **After:** Only users with the ADMIN role can invoke `processMonthEndCleanup()`. Callers lacking the role receive an `AccessDeniedException`, which is translated to HTTP 403 Forbidden by `ExceptionTranslationFilter` for HTTP requests.

**Method Return & Contract:**
- Return type unchanged (void).
- The method's functional behavior (locating and deleting voided invoices) is preserved; only the authorization gate is added.
- In scheduled/batch contexts without an HTTP security context, the application must establish a security context with ADMIN credentials before invoking this method, or catch and handle `AccessDeniedException` as appropriate to the batch runtime.

**No unintended side effects:** The fix changes only the authorization enforcement and does not alter data flow, API signatures, or error handling paths beyond the expected authorization denial.
