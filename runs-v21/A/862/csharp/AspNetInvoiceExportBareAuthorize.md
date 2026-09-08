## Verdict

CONFIRMED - CWE-862 (Missing Authorization)

## Source

The `Export` method at line 17 has authentication (`[Authorize]`) but lacks ownership verification. The method loads and returns an invoice without checking whether the current user owns that invoice. An authenticated user can access any invoice by modifying the `invoiceId` parameter, regardless of account ownership.

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
        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        // Check ownership: ensure the current user's account matches the invoice's account
        var userAccountId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userAccountId) || invoice.AccountId != userAccountId)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation

The `[Authorize]` attribute alone confirms the user is authenticated but does not authorize them to access this specific invoice. After loading the invoice, the fix retrieves the current user's account ID from their claims (using `ClaimTypes.NameIdentifier`, a standard ASP.NET Core pattern) and compares it against the invoice's `AccountId`. If the user's account ID is missing or does not match the invoice owner's account, the method returns `Forbid()`, denying access.

This implements ownership-based authorization: only the user who owns the invoice account can export that invoice.
