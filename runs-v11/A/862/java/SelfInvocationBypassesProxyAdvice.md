## Verdict

Authorization required. The `processMonthEndCleanup()` method bypasses the `@PreAuthorize` check on `deleteInvoice()` because Spring AOP authorization advice does not apply to self-invocations within the same bean instance. The protected operation executes without authorization validation when called from an internal method.

## Source

Line 33: `deleteInvoice(invoice.getId());` within `processMonthEndCleanup()`. When called as `this.deleteInvoice(...)` from the same class instance, the call does not pass through the Spring proxy that enforces the `@PreAuthorize("hasRole('ADMIN')")` annotation on `deleteInvoice()`.

## Fix

Extract the core deletion logic into a private helper method, and apply authorization to the batch method explicitly. Both `deleteInvoice()` and `processMonthEndCleanup()` require ADMIN role because both perform the same sensitive operation: deletion of invoices.

```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteInvoice(Long id) {
    performDeleteInvoice(id);
}

@PreAuthorize("hasRole('ADMIN')")
public void processMonthEndCleanup() {
    List<Invoice> voidedInvoices = invoiceRepository.findAllByVoidedTrue();
    for (Invoice invoice : voidedInvoices) {
        performDeleteInvoice(invoice.getId());
    }
}

private void performDeleteInvoice(Long id) {
    invoiceRepository.deleteById(id);
}
```

## Explanation

Spring AOP authorization advice is applied only to method calls that pass through the proxy. When a method calls another method on the same instance using `this.methodName()` (implicit in internal calls), the call is a direct Java method invocation that bypasses the proxy and thus bypasses `@PreAuthorize` checks.

The fix separates authorization policy from the shared deletion implementation: both public entry points (`deleteInvoice` for direct calls and `processMonthEndCleanup` for batch operations) declare their authorization requirements explicitly via `@PreAuthorize("hasRole('ADMIN')")`. Both methods then delegate the actual deletion to a private `performDeleteInvoice()` method that contains no authorization logic, allowing each public method to enforce its own access control through the proxy.

This ensures that:
- Direct calls to `deleteInvoice()` via HTTP endpoints check authorization through the proxy
- The batch job `processMonthEndCleanup()` is also protected and cannot be executed without ADMIN authorization
- The deletion logic itself is not duplicated
