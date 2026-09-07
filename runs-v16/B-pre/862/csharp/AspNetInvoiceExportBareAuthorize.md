## Verdict

Exploitable

## Source

`invoiceId` parameter supplied by the authenticated user in the HTTP request URL.

## Fix

**Vulnerable code (line 17-28):**
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

**Fixed code (controller):**
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

        // Verify the authenticated user owns this invoice before granting access
        var authResult = await _authorizationService.AuthorizeAsync(User, invoice, "CanExportInvoice");
        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

**Supporting handler and configuration (Program.cs):**

Register the authorization requirement and handler in the dependency injection and authorization configuration:

```csharp
// In Program.cs, after AddAuthentication:
builder.Services.AddScoped<IAuthorizationHandler, InvoiceOwnershipHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanExportInvoice", policy =>
    {
        policy.Requirements.Add(new InvoiceOwnershipRequirement());
    });
});

// Define the requirement and handler classes:
public class InvoiceOwnershipRequirement : IAuthorizationRequirement { }

public class InvoiceOwnershipHandler : AuthorizationHandler<InvoiceOwnershipRequirement, InvoiceExport>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        InvoiceOwnershipRequirement requirement,
        InvoiceExport invoice)
    {
        if (context.User == null || invoice == null)
        {
            return Task.CompletedTask;
        }

        // Extract the current user's account ID from claims
        var userAccountId = context.User.FindFirst("account_id")?.Value;
        
        // Compare with the invoice's owner account ID
        if (!string.IsNullOrEmpty(userAccountId) && userAccountId == invoice.AccountId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
```

## Explanation

The vulnerability occurs because `[Authorize]` alone confirms authentication (the user is logged in) but performs no authorization check (whether that user is permitted to access this specific resource). An authenticated attacker can export any invoice by changing the `invoiceId` URL parameter, because there is no ownership verification.

The fix adds a resource-based authorization check using `IAuthorizationService.AuthorizeAsync()` with an authorization handler that compares the authenticated user's account ID against the invoice's owner (`AccountId` field). The handler is derived from `AuthorizationHandler<TRequirement, TResource>`, and `context.Succeed()` is called only when ownership matches. This ensures that each invoice export is permitted only by its owner.

The fix returns `Forbid()` (HTTP 403) when the authorization check fails for an authenticated caller. This is correct here because the denial is based on permissions/ownership, not on authentication status; an unauthenticated caller is already rejected by the `[Authorize]` attribute and never reaches the handler.

## Behaviour changes

- **Added dependency**: `IAuthorizationService` injected into the controller constructor. This is part of ASP.NET Core's built-in authorization service and is available after calling `builder.Services.AddAuthorization()` in Program.cs, which is standard in all ASP.NET Core applications.
- **Added method call**: `_authorizationService.AuthorizeAsync(User, invoice, "CanExportInvoice")` performs the ownership check. This adds minimal latency (a single claim lookup and string comparison) to each request.
- **Conditional return**: The method now returns `Forbid()` (403) when `authResult.Succeeded` is false, where the original code returned 200 for any authenticated user. This prevents unauthorized access.
- **Handler registration required**: The application's startup configuration must register the `InvoiceOwnershipHandler` and define the "CanExportInvoice" policy. This is a one-time configuration in Program.cs.
- **Claim dependency**: The handler assumes the authenticated user's account ID is available in a claim named `account_id`. If the claim name differs in your application, update the `FindFirst("account_id")` call to match your identity provider's claim names.
- **Return value preservation**: The method still returns `File(...)` with the same content type and filename when authorization succeeds, preserving the original behavior for authorized callers.
