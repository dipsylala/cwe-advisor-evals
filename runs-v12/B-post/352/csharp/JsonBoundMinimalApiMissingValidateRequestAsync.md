## Verdict

Exploitable. The endpoint processes an authenticated state-changing request without CSRF token validation.

## Source

Attacker-controlled POST request with JSON-encoded body to `/account/email`.

## Fix

**Vulnerable code:**

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();
```

**Fixed code:**

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context, IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(context);
    
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();
```

## Explanation

The endpoint is a JSON-bound minimal API that modifies authenticated state without validating a CSRF token. ASP.NET Core's `app.UseAntiforgery()` middleware only automatically validates form-bound endpoints; JSON-bound endpoints require explicit validation by injecting `IAntiforgery` and calling `await antiforgery.ValidateRequestAsync(context)`. The fix injects the service as a parameter and validates the token at the top of the handler before any state-changing operation, enforcing verification that the request originated from the application itself via a server-controlled token in the `RequestVerificationToken` header.

## Behaviour changes

None. The validation call enforces the existing antiforgery middleware configuration already present in the application (line 9: `builder.Services.AddAntiforgery()` and line 16: `app.UseAntiforgery()`). The call does not alter the handler's return values, arguments to downstream methods, or error handling - it only adds a security gate before the state-changing operation.
