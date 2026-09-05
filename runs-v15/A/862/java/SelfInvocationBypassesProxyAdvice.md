## Verdict
Confirmed. The `processMonthEndCleanup()` method invokes `deleteInvoice()` through self-invocation on line 33, bypassing Spring Security's `@PreAuthorize` check. Since Spring AOP proxies do not intercept same-class method calls, an attacker could invoke `processMonthEndCleanup()` without ADMIN authorization and delete all voided invoices, circumventing the access control on `deleteInvoice()`.

## Source
Line 33 calls `deleteInvoice(invoice.getId())` within the same service instance, which bypasses the `@PreAuthorize("hasRole('ADMIN')")` annotation on the target method because the call does not route through the Spring proxy.

## Fix
Refactor `processMonthEndCleanup()` to delete voided invoices directly via the repository, avoiding self-invocation of the authorized method:

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
    @PreAuthorize("hasRole('ADMIN')")
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            invoiceRepository.deleteById(invoice.getId());
        }
    }
}
```

## Explanation
The vulnerability stems from Spring's AOP proxy limitation: method-level security annotations only apply when the method is called through the proxy (external callers), not when called directly within the same class instance. The fix uses two strategies: (1) add `@PreAuthorize` to `processMonthEndCleanup()` to ensure the entry point is protected, and (2) replace the self-invocation with a direct call to `invoiceRepository.deleteById()`, making authorization checks explicit and unavoidable. This ensures that authorization is enforced at the batch job's entry point, preventing unauthorized callers from deleting invoices regardless of how they invoke the cleanup operation.
