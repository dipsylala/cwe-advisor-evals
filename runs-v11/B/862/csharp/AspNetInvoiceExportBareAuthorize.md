## Verdict
Exploitable. The `Export` action verifies the caller is authenticated with `[Authorize]` but does not verify the caller is authorized to access the specific invoice. An authenticated user can change the `invoiceId` parameter to request invoices belonging to other accounts.

## Source
HTTP request parameter `invoiceId` (line 19, method signature). The value is passed directly to `_invoices.LoadForExportAsync(invoiceId)` without checking ownership.

## Fix

**Vulnerable code (line 17-28):**
```csharp
    [Authorize]
    [HttpGet("{invoiceId}/export")]
    public async System.Threading.Tasks.Task<IActionResult> Export(string invoiceId)
    {
        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
```

**Fixed code:**
```csharp
    [Authorize]
    [HttpGet("{invoiceId}/export")]
    public async System.Threading.Tasks.Task<IActionResult> Export(string invoiceId)
    {
        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        // Verify the user has authorization to access this invoice's account
        var userAccountId = User.FindFirst("account_id")?.Value;
        if (string.IsNullOrEmpty(userAccountId) || userAccountId != invoice.AccountId)
        {
            return NotFound(); // Return 404 to avoid confirming resource exists
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
```

## Explanation
The fix adds a resource-level authorization check that verifies the authenticated user's `account_id` claim matches the invoice's `AccountId` before returning the PDF. This prevents an authenticated user from accessing invoices belonging to other accounts by guessing or manipulating the `invoiceId` parameter. The check returns 404 (NotFound) for both "invoice does not exist" and "invoice exists but you don't own it" cases, following the principle that an identifiable resource's ownership should not be confirmed through different status codes—doing so would allow enumeration of the identifier space.

## Behaviour changes
- Added a claim-based ownership check using `User.FindFirst("account_id")?.Value` before the file is returned.
- Returns `NotFound()` (404) when the user's `account_id` claim does not match the invoice's `AccountId`, preventing unauthorized access.
- Returns 404 for both "resource not found" and "access denied" scenarios (instead of 200 for the second case), eliminating the ability to infer resource existence through status code differences. This requires that the client's HTTP access is routed through cookie or bearer token authentication where the `account_id` claim is populated by the identity provider at login time.
