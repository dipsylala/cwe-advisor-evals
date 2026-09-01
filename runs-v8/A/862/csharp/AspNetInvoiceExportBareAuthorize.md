## Verdict
Confirmed. The `[Authorize]` attribute verifies only that the user is authenticated, not that they have permission to access the specific invoice. Line 17 implements authentication without authorization checks, allowing any authenticated user to export any invoice by changing the `invoiceId` parameter.

## Source
The Export method uses `[Authorize]` at line 17, which enforces authentication but does not validate ownership or resource-level permissions. The `invoiceId` parameter is passed directly to `LoadForExportAsync()` without confirming the current user owns or has access to that invoice. The repository layer does not filter by user identity.

## Fix
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

        // Retrieve the current user's account ID from claims
        var userAccountId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value 
            ?? User.FindFirst("AccountId")?.Value;
        
        // Verify the user owns this invoice
        if (string.IsNullOrEmpty(userAccountId) || invoice.AccountId != userAccountId)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation
The fix adds resource-level authorization by extracting the current user's account ID from their claims and comparing it to the invoice's `AccountId`. If the user is not the owner, the method returns `Forbid()` (HTTP 403). This prevents authenticated users from accessing invoices belonging to other accounts. The authorization check must occur after loading the invoice but before returning any data, ensuring only authorized users can access sensitive invoice exports.
