## Verdict

Authorization check missing. The `[Authorize]` attribute verifies authentication but does not verify that the authenticated user owns the requested invoice. An attacker can access any invoice by manipulating the `invoiceId` parameter.

## Source

The vulnerability is in `InvoiceExportController.Export()` at line 17. The method accepts an `invoiceId` parameter from the URL route, retrieves the invoice from the repository, and returns it without verifying that the authenticated user is authorized to access that specific invoice.

The `InvoiceExport` record contains an `AccountId` field (visible in `InvoiceRepository.cs` line 9), indicating that invoices are scoped to user accounts. The controller does not check whether the current user's account matches the invoice's `AccountId`.

## Fix

```csharp
using System.Security.Claims;
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
        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        var userAccountId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userAccountId == null || invoice.AccountId != userAccountId)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation

The fix adds an authorization check after retrieving the invoice:

1. Extract the current user's account ID from the `NameIdentifier` claim via `User.FindFirst(ClaimTypes.NameIdentifier)?.Value`. This claim represents the user's unique identifier or account ID.

2. Check whether the retrieved invoice's `AccountId` matches the user's account ID. If they do not match, or if the user has no `NameIdentifier` claim, the user is not authorized to access this invoice.

3. Return `Forbid()` (HTTP 403) if the user lacks authorization. This response indicates that the resource exists but the user does not have permission to access it, distinguishing it from a 404 (not found).

4. Only serve the invoice PDF if authorization succeeds.

This implements the principle of least privilege: each user can access only invoices that belong to their own account. The authorization check is per-resource, verifying ownership before the expensive File operation.
