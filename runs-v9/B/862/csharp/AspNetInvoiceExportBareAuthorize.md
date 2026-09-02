## Verdict

Exploitable. Confidence: high.

`InvoiceExportController.Export` carries `[Authorize]`, which only confirms the caller is authenticated - it performs no check that the caller is entitled to the specific invoice being requested. `invoiceId` is attacker-controlled (a route segment) and is passed straight into `InvoiceRepository.LoadForExportAsync`, which loads and returns the record for any ID with no scoping to the caller. Any authenticated user can therefore enumerate `invoiceId` values and download PDFs belonging to other accounts. This is CWE-862, not CWE-306 (a check runs - authentication - but the resource-ownership check is absent) and not CWE-863 (there is no ownership logic present to be flawed).

## Source

- Source: `invoiceId` route parameter on `GET api/invoices/{invoiceId}/export` (`InvoiceExportController.cs:19`), fully attacker-controlled.
- Flow: `invoiceId` -> `_invoices.LoadForExportAsync(invoiceId)` (`InvoiceExportController.cs:21`) -> `InvoiceRepository.LoadForExportAsync` (`InvoiceRepository.cs:7-10`), which loads the record keyed only on `invoiceId`.
- Sink: `return File(invoice.PdfBytes, "application/pdf", invoice.FileName);` (`InvoiceExportController.cs:27`) - serves the loaded invoice's bytes to the caller with no check that the caller owns the invoice's account (`invoice.AccountId`).
- Sink contract: `LoadForExportAsync` returns `InvoiceExport?` (null on not-found, mapped to `NotFound()`); it discards nothing security-relevant today but the loaded `AccountId` is never read by the caller; it takes no caller-identity argument; failure behaviour is "return null" -> 404, no exception path.

## Fix

No third-party library is needed; this is a missing resource-ownership check, closed with an in-process scoped lookup per the CWE-862 C# guidance's "scope the lookup itself" pattern for a guessable object identifier.

Vulnerable code (`InvoiceExportController.cs`):

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
        // [Authorize] only checks the caller is authenticated - no ownership check
        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

Vulnerable code (`InvoiceRepository.cs`):

```csharp
namespace Cases.Authorization;

public sealed record InvoiceExport(byte[] PdfBytes, string FileName, string AccountId);

public sealed class InvoiceRepository
{
    // Loads by invoiceId only - no caller/account scoping
    public System.Threading.Tasks.Task<InvoiceExport?> LoadForExportAsync(string invoiceId)
    {
        return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(new InvoiceExport(System.Array.Empty<byte>(), invoiceId + ".pdf", "acct-42"));
    }
}
```

Fixed code (`InvoiceExportController.cs`):

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
        var callerAccountId = User.FindFirstValue("account_id");
        if (string.IsNullOrEmpty(callerAccountId))
        {
            // Fail closed: an authenticated principal with no account claim cannot be scoped to any resource
            return Forbid();
        }

        var invoice = await _invoices.LoadForExportAsync(invoiceId, callerAccountId);
        if (invoice is null)
        {
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

Fixed code (`InvoiceRepository.cs`):

```csharp
namespace Cases.Authorization;

public sealed record InvoiceExport(byte[] PdfBytes, string FileName, string AccountId);

public sealed class InvoiceRepository
{
    // Scoped to the caller's account: WHERE invoiceId = @invoiceId AND account_id = @callerAccountId
    public System.Threading.Tasks.Task<InvoiceExport?> LoadForExportAsync(string invoiceId, string callerAccountId)
    {
        var record = new InvoiceExport(System.Array.Empty<byte>(), invoiceId + ".pdf", "acct-42");
        if (record.AccountId != callerAccountId)
        {
            return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(null);
        }

        return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(record);
    }
}
```

## Explanation

The fix adds the resource-ownership check `[Authorize]` was never doing: it reads the caller's own account identifier from the authenticated principal's claims and threads it into the repository lookup, which now scopes the record by both `invoiceId` and the caller's account before returning it. Because `invoiceId` is a guessable, non-secret identifier, the ownership mismatch is folded into the same lookup that already produces a 404 for a nonexistent invoice, so "not yours" and "does not exist" are indistinguishable to the caller - this avoids turning the endpoint into an enumeration oracle, per the CWE-862 guidance's status-code rule for guessable identifiers. The check happens against the server-loaded record's `AccountId`, never a client-supplied value, so it cannot be bypassed by a forged parameter.

## Behaviour changes

- `InvoiceRepository.LoadForExportAsync` gained a second parameter, `callerAccountId`, and now returns `null` when the loaded record's `AccountId` does not match it. Reason: this is the ownership check the finding is about; without it the endpoint stays exploitable.
- The controller now reads a `"account_id"` claim from `User` and returns `Forbid()` (403) when it is absent, before any repository call. Reason: fail-closed behaviour per the CWE-862 guidance - if the authorization decision cannot be evaluated (no account claim to compare), the request is denied rather than defaulted to allow. This is a new response path with no equivalent in the original code.
- Response for another account's `invoiceId`: was 200 with the PDF body, is now 404 (identical status and body shape to a nonexistent `invoiceId`, per the guidance's enumeration-oracle guidance). This is the intended effect of the fix.
- All other behaviour - `NotFound()` for a truly nonexistent ID, the `File(...)` response shape and content-type for a caller's own invoice - is unchanged.
- Assumption: the claim carrying the caller's account identifier is named `"account_id"`. Neither provided file shows an existing claims-issuing or account-resolution mechanism, so this name is inferred from the domain field `InvoiceExport.AccountId` rather than confirmed against the application's actual identity setup; a reviewer should replace it with whatever claim type or user-lookup the real system already uses to resolve the caller's account. Confidence on the fix mechanism itself (scope the lookup by caller identity) is high; confidence on this specific claim name is low.
