## Verdict

CWE-862: Missing Authorization. The Export endpoint has only `[Authorize]` (authentication) with no resource-based authorization. An authenticated user can access any invoice by guessing the invoiceId, regardless of ownership.

## Source

**Location**: InvoiceExportController.cs, line 17-28, method Export.

**Data flow**: 
- invoiceId parameter (user-controlled route value) → LoadForExportAsync(invoiceId) → returns InvoiceExport without ownership verification → returned directly to caller via File()

**Gap**: The endpoint verifies authentication via `[Authorize]` but never checks whether the current user owns the specific invoice identified by invoiceId. The repository Load method accepts any invoiceId without a WHERE clause filtering by the authenticated user's account.

## Fix

Add resource-based authorization using `IAuthorizationService.AuthorizeAsync` to verify ownership before returning the invoice. Define an authorization requirement and handler that compares the current user's AccountId claim against the loaded invoice's AccountId field.

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
    private readonly IAuthorizationService _authorizationService;

    public InvoiceExportController(InvoiceRepository invoices, IAuthorizationService authorizationService)
    {
        _invoices = invoices;
        _authorizationService = authorizationService;
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

        // Check if the current user owns this invoice
        var authorizationResult = await _authorizationService.AuthorizeAsync(User, invoice, "InvoiceOwnershipPolicy");
        if (!authorizationResult.Succeeded)
        {
            // Return NotFound for ownership failures to avoid confirming invoice existence
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

### File: InvoiceOwnershipHandler.cs

```csharp
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Cases.Authorization;

public class InvoiceOwnershipRequirement : IAuthorizationRequirement
{
}

public class InvoiceOwnershipHandler : AuthorizationHandler<InvoiceOwnershipRequirement, InvoiceExport>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        InvoiceOwnershipRequirement requirement,
        InvoiceExport resource)
    {
        var userAccountId = context.User.FindFirst("AccountId")?.Value;
        
        if (!string.IsNullOrEmpty(userAccountId) && userAccountId == resource.AccountId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
```

## Explanation

The fix adds resource-level authorization to the Export endpoint. After the invoice is loaded, `IAuthorizationService.AuthorizeAsync` is invoked with the loaded invoice as the resource and the "InvoiceOwnershipPolicy" policy name. The `InvoiceOwnershipHandler` derives from `AuthorizationHandler<TRequirement, TResource>` and succeeds the authorization requirement only when the authenticated user's AccountId claim matches the invoice's AccountId field, per the C# guidance.

The authorization check runs through the centralized `IAuthorizationService` rather than inline, following the pattern recommended in the guidance for consistency with sibling endpoints. For a guessable identifier like invoiceId, an ownership failure returns `NotFound()` rather than `Forbid()` to avoid confirming invoice existence to unauthorized users.

Assumptions: The authenticated user has an "AccountId" claim in their ClaimsPrincipal containing the account identifier. This claim should be populated by the application's authentication handler. In Program.cs, register the handler and policy: `services.AddSingleton<IAuthorizationHandler, InvoiceOwnershipHandler>();` and `builder.Services.AddAuthorization(options => options.AddPolicy("InvoiceOwnershipPolicy", policy => policy.Requirements.Add(new InvoiceOwnershipRequirement())));`

## Behaviour changes

- Export endpoint now denies access and returns NotFound (404) to authenticated users who do not own the invoice, rather than returning the PDF file.
- Ownership check is applied to every export request, enforcing resource-level authorization alongside authentication.
- HTTP status remains NotFound (404) for both non-existent invoices and invoices not owned by the caller, preventing enumeration of the invoice identifier space.
- No change to the endpoint's accessibility for authenticated users who own the requested invoice.
