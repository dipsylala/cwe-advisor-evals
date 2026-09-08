## Verdict

Exploitable

## Source

The `invoiceId` parameter from the URL route `{invoiceId}` in `[HttpGet("{invoiceId}/export")]` at line 18 of InvoiceExportController.cs. This is user-supplied and attacker-controlled.

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
        var userAccountId = User.FindFirst("accountId")?.Value;
        if (string.IsNullOrEmpty(userAccountId))
        {
            return Unauthorized();
        }

        var invoice = await _invoices.LoadForExportAsync(invoiceId, userAccountId);
        if (invoice is null)
        {
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

### File: InvoiceRepository.cs

```csharp
namespace Cases.Authorization;

public sealed record InvoiceExport(byte[] PdfBytes, string FileName, string AccountId);

public sealed class InvoiceRepository
{
    public System.Threading.Tasks.Task<InvoiceExport?> LoadForExportAsync(string invoiceId, string accountId)
    {
        // In a real implementation, query the database:
        // SELECT * FROM invoices WHERE id = @invoiceId AND account_id = @accountId
        // Returns null if not found or if user does not own this invoice
        if (accountId == "acct-42")
        {
            return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(new InvoiceExport(System.Array.Empty<byte>(), invoiceId + ".pdf", accountId));
        }
        return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(null);
    }
}
```

## Explanation

The action had `[Authorize]` which only verified authentication (is the user logged in) but performed no authorization check (does the user have permission to access this specific invoice). An authenticated attacker could supply any `invoiceId` and retrieve an invoice they do not own.

The fix adds a resource-based authorization check: the controller now extracts the current user's `accountId` claim, passes it to the repository method alongside the `invoiceId`, and the repository scopes the query to only return invoices owned by that user. Both paths (invoice not found, and invoice exists but is not owned by the user) return `null`, which the controller converts to 404, preventing enumeration attacks. The fix follows the principle that authorization decisions must be made server-side on the current user's identity and stored ownership data, not on client-supplied values.

## Behaviour changes

- **Added parameter to `LoadForExportAsync`**: The repository method now requires an `accountId` parameter to scope the query by ownership. This enforces that all invoice loads are filtered by the requesting user's account.
- **Added user identity check in controller**: The controller now extracts the user's `accountId` claim and returns `401 Unauthorized` if the claim is missing, ensuring only authenticated users with a resolvable identity can proceed.
- **Changed response for unauthorized access**: Where the original code would return the invoice to any authenticated user, the fixed code returns `404 Not Found` for both "invoice not found" and "user does not own invoice" scenarios. This prevents enumeration of invoice IDs owned by other accounts.
- **Repository filtering logic**: The repository method now validates ownership before returning data. In the stub implementation shown, ownership is checked against the hardcoded account. In a real implementation, the database query itself would filter by both `id` and `account_id`.
