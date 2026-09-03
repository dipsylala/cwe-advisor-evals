## Verdict

CONFIRMED. The `processMonthEndCleanup()` method calls `deleteInvoice()` on line 33 without authorization enforcement. Although `deleteInvoice()` is annotated with `@PreAuthorize("hasRole('ADMIN')")`, a self-invocation from within the same class bypasses Spring AOP proxies, allowing the deletion to proceed without the authorization check being evaluated.

## Source

`processMonthEndCleanup()` is an entry point for a nightly batch job that iterates over voided invoices and invokes `deleteInvoice()` for each. The method has no `@PreAuthorize` annotation and no explicit authorization check.

## Fix

Extract `deleteInvoice()` into a separate service class to ensure Spring's proxy intercepts the authorization check:

**Create a new interface:**
```java
public interface DeleteInvoiceService {
    void deleteInvoice(Long id);
}
```

**Create a new implementation:**
```java
@Service
public class DeleteInvoiceServiceImpl implements DeleteInvoiceService {

    private final InvoiceRepository invoiceRepository;

    public DeleteInvoiceServiceImpl(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteInvoice(Long id) {
        invoiceRepository.deleteById(id);
    }
}
```

**Update InvoiceService to inject and use the service:**
```java
@Service
public class InvoiceService {

    private final InvoiceRepository invoiceRepository;
    private final DeleteInvoiceService deleteInvoiceService;

    public InvoiceService(InvoiceRepository invoiceRepository, DeleteInvoiceService deleteInvoiceService) {
        this.invoiceRepository = invoiceRepository;
        this.deleteInvoiceService = deleteInvoiceService;
    }

    /**
     * Nightly batch job entry point: purges invoices that were voided
     * during the billing cycle and never finalized.
     */
    public void processMonthEndCleanup() {
        List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
        for (Invoice invoice : voidedInvoices) {
            deleteInvoiceService.deleteInvoice(invoice.getId());
        }
    }
}
```

## Explanation

Spring AOP method security is proxy-based. When a method within a class invokes another method on the same class (self-invocation via `this`), the call bypasses the proxy entirely, circumventing the `@PreAuthorize` enforcement. By extracting the authorized operation into a separate service class that is injected as a dependency, every call passes through the Spring proxy, ensuring the authorization check is evaluated. The batch job's authorization requirement is enforced at the injection point, protecting the sensitive delete operation from unprivileged callers regardless of how `processMonthEndCleanup()` is invoked.

## Behaviour changes

- The `deleteInvoice()` operation is now accessible only through the `DeleteInvoiceService` bean, making self-invocation bypass impossible.
- The `@PreAuthorize("hasRole('ADMIN')')` annotation on the extracted service is now enforced for all callers, including the batch job.
- If `processMonthEndCleanup()` is invoked outside an authenticated security context (e.g., scheduled task), the first call to `deleteInvoiceService.deleteInvoice()` will raise `AccessDeniedException`, which must be caught and handled appropriately by the batch job orchestration layer.
