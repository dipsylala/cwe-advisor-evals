## Verdict

CONFIRMED

## Source

The vulnerability originates from the `invoiceId` parameter in the URL path:
```
GET /api/invoices/{invoiceId}/export
```

This parameter is attacker-controlled and is passed directly to `_invoices.LoadForExportAsync(invoiceId)` without any ownership verification.

## Fix

### File: InvoiceExportController.cs

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cases.Authorization;

[ApiController]
[Route("api/invoices")]
public sealed class InvoiceExportController : ControllerBase
{
    private readonly InvoiceRepository _invoices;

    public InvoiceExportController(InvoiceRepository invoices)
    {
        _invoices = invoices;
    }

    [Authorize]
    [HttpGet("{invoiceId}/export")]
    public async System.Threading.Tasks.Task<IActionResult> Export(string invoiceId)
    {
        // Extract the authenticated user's account ID from claims
        var userAccountId = User.FindFirst("account_id")?.Value;
        if (string.IsNullOrEmpty(userAccountId))
        {
            return Forbid();
        }

        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        // Verify both that invoice exists and that the user owns it
        // Return 404 for both "not found" and "not owned" to prevent enumeration
        if (invoice is null || invoice.AccountId != userAccountId)
        {
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation

The original code had only an `[Authorize]` attribute, which verifies the caller is authenticated (logged in) but makes no check on whether they are permitted to access the specific invoice. This is a resource-level authorization gap.

The fix adds an ownership check: after loading the invoice, it compares the authenticated user's `account_id` claim to the invoice's `AccountId` field. The check is performed against the server-loaded invoice object (not a client-supplied value), ensuring the authorization decision is based on authoritative data.

If the user's account ID claim is missing (authorization decision cannot be evaluated), the endpoint returns `Forbid()` per the "fail closed" principle. If the invoice does not exist or the user does not own it, both cases return `NotFound()` with an identical response, preventing attackers from enumerating which invoice IDs exist by observing different error codes.

## Behaviour changes

- **Added check**: The endpoint now verifies the authenticated user owns the invoice before returning the PDF.
- **Changed response code**: An authenticated user without ownership now receives `404 Not Found` instead of `200 OK`, preventing unauthorized access.
- **Claim dependency**: The fix assumes the authenticated user's principal includes an `account_id` claim. If this claim is missing or incorrectly configured, the endpoint will deny access (returns `Forbid()`).
- **Security posture**: Prevents horizontal privilege escalation where an authenticated user could access other users' invoices via URL parameter manipulation.
