## Verdict

Exploitable

## Source

`EmailChangeRequest request` parameter on line 18 - untrusted HTTP POST body

## Fix

**Vulnerable Code:**
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

**Fixed Code:**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context, IAntiforgery antiforgery) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await antiforgery.ValidateRequestAsync(context);
    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();
```

## Explanation

The endpoint binds its body from JSON (`EmailChangeRequest request`), which means `app.UseAntiforgery()` middleware does not enforce CSRF token validation—it only records the check. For JSON-bound minimal API endpoints, you must explicitly inject `IAntiforgery` and call `await antiforgery.ValidateRequestAsync(context)` before processing the state-changing request. The validation call verifies that the request includes a valid anti-forgery token in the header (defaulting to `RequestVerificationToken`) that is bound to the authenticated user's session, preventing attackers from forging requests on behalf of authenticated users.

## Behaviour changes

Adds `IAntiforgery antiforgery` parameter injection and a call to `await antiforgery.ValidateRequestAsync(context)` before processing the email update. If validation fails, the endpoint throws `AntiforgeryValidationException`, which the ASP.NET Core runtime converts to a 400 Bad Request response. This is the intended security-hardening behavior: requests without valid CSRF tokens are now rejected before reaching the service layer.
