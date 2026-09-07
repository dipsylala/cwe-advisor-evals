## Verdict
Confirmed CWE-862 (Missing Authorization). The controller checks authentication via `[Authorize]` but does not verify the user has access to the specific invoice resource.

## Source
Line 17–28 in InvoiceExportController.cs: The `Export` action accepts an `invoiceId` parameter and loads the invoice via `_invoices.LoadForExportAsync(invoiceId)` without validating that the authenticated user owns or has permission to access that invoice.

## Fix

### File: InvoiceExportController.cs
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

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
        var userAccountId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("account_id")?.Value;

        if (string.IsNullOrEmpty(userAccountId))
        {
            return Unauthorized();
        }

        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        if (invoice.AccountId != userAccountId)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation
The fix adds resource-level authorization by comparing the authenticated user's account identifier (extracted from claims) with the invoice's `AccountId`. After loading the invoice, the code verifies ownership before returning it. If the user's account does not match the invoice's account, a 403 Forbidden response is returned. This prevents one user from accessing another user's invoice even though both are authenticated.
