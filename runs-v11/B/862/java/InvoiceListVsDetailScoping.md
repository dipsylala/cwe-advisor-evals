## Verdict

**CWE-862 (Missing Authorization)** confirmed and remediable.

The `listInvoices()` endpoint at line 26 calls `repository.findAll()` without authorization, returning all invoices in the system to any authenticated user. The method omits the `Authentication` parameter and must scope the result to only the caller's own invoices, matching the pattern established by `getInvoice()`.

## Source

**File:** `InvoiceController.java`, line 26  
**Sink:** `return repository.findAll();`

**Data flow:**
1. HTTP GET `/api/invoices` reaches `listInvoices()` as an authenticated user
2. No authentication parameter is accepted by the method
3. `repository.findAll()` is called unconditionally, returning all invoices
4. The unfiltered list is returned to the caller

**Gap:** The endpoint verifies the caller is logged in (authentication filter) but never checks whether the caller owns the records (authorization). The `InvoiceRepository` provides `findByOwnerUsername()` to scope results by owner, but the controller never invokes it.

## Fix

**Vulnerable code:**
```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices() {
    return repository.findAll();  // CWE-862: Returns all invoices, not just caller's
}
```

**Fixed code:**
```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices(Authentication authentication) {
    return repository.findByOwnerUsername(authentication.getName());
}
```

## Explanation

The fix adds the `Authentication` parameter (provided by Spring Security to the request context) and passes the authenticated user's name to `repository.findByOwnerUsername()`. This scopes the query to invoices owned by the caller alone, matching the ownership check pattern used in `getInvoice()`. The method now enforces authorization at the repository level, the recommended pattern described in CWE-862 guidance for Java/Spring: scope the lookup itself (WHERE id = ? AND owner_id = ?) rather than returning all records and filtering on the client side.

## Behaviour changes

**Before:** Any authenticated user receives all system invoices via GET `/api/invoices`

**After:** GET `/api/invoices` returns only invoices where the `ownerUsername` field matches the authenticated caller's name, via `findByOwnerUsername()`

**Testing:** Confirm with a MockMvc test calling the endpoint as user A, asserting the result contains only that user's invoices; then as user B, asserting the same (and that user A's invoices are absent).
