## Verdict

Exploitable. Any authenticated user can access invoices belonging to other users.

## Source

**URL parameter**: `invoiceId` from the HTTP GET route `{invoiceId}/export`

**Data flow**: The `invoiceId` is passed to `LoadForExportAsync()` which retrieves the invoice without verifying ownership. The loaded invoice is then returned directly to the caller via `File()`.

**Missing gate**: The endpoint carries `[Authorize]` which only verifies authentication (caller is logged in). It does not verify authorization — whether the caller owns this specific invoice. Any authenticated user can guess or enumerate invoice IDs and download another user's invoice PDF.

## Fix

**Vulnerable code:**
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

    // Verify the authenticated user owns this invoice
    var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId) || invoice.AccountId != userId)
    {
        return Forbid();
    }

    return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
}
```

## Explanation

The fix adds a resource-level ownership check after loading the invoice. It compares the authenticated user's ID (from their claims principal) against the invoice's `AccountId` field, which represents the owner. If the user does not own the invoice, the method returns `Forbid()` instead of the file. This closes the horizontal privilege escalation where any authenticated user could access another user's data by changing the invoice ID in the URL. The check runs on the server before returning sensitive data, complying with the principle that every sensitive action must verify both authentication and authorization.

## Behaviour changes

**Arguments changed**: None. `LoadForExportAsync` is called identically.

**New check added**: A direct ownership comparison between the current user's claim (`ClaimTypes.NameIdentifier`) and the loaded invoice's `AccountId`. This is a resource-based authorization check; it is additive and does not alter the behavior of the repository call or file return.

**Return path added**: Returns `Forbid()` for authenticated users who do not own the invoice. This is semantically correct: the caller is authenticated but lacks permission, so a 403 Forbidden status is appropriate. Unauthenticated callers are already denied by `[Authorize]`.

**Sink contract preserved**: The original sink (`File()`) is reached identically when authorization succeeds. Its arguments, return value, and side effects are unchanged.
