## Verdict

**Confirmed CWE-862: Missing Authorization**

The `[Authorize]` attribute on line 17 only verifies that the user is authenticated, not that they are authorized to access the specific invoice being exported. Any authenticated user can call the endpoint with an arbitrary `invoiceId` and retrieve invoices belonging to other users.

## Source

In `InvoiceExportController.cs`, lines 17-28:

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

The controller accepts an `invoiceId` parameter directly from the URL without verifying that the authenticated user owns or has permission to access that invoice.

## Fix

```csharp
[Authorize]
[HttpGet("{invoiceId}/export")]
public async System.Threading.Tasks.Task<IActionResult> Export(string invoiceId)
{
    var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
    {
        return Unauthorized();
    }

    var invoice = await _invoices.LoadForExportAsync(invoiceId);
    if (invoice is null)
    {
        return NotFound();
    }

    if (invoice.AccountId != userId)
    {
        return Forbid();
    }

    return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
}
```

## Explanation

The original code performs authentication (via `[Authorize]`) but skips authorization—the critical check that verifies the current user has the right to access the requested resource.

The fix extracts the authenticated user's ID from the claims principal and compares it against the invoice's `AccountId`. If they do not match, the endpoint returns `Forbid()` (HTTP 403), denying access to invoices the user does not own. This ensures that each user can only export invoices they have permission to access, closing the privilege escalation path that allowed horizontal access to other users' data.
