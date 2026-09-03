## Verdict
CONFIRMED. The POST endpoint at `/account/email` performs a state-changing operation on authenticated user data but does not validate the CSRF token before processing the request, making it vulnerable to cross-site request forgery attacks.

## Source
Line 27 is the sink: `await accounts.UpdateEmailAsync(userId, request.NewEmail);` is called without prior CSRF token validation despite authentication being required on this endpoint.

The vulnerability chain: an unauthenticated attacker can craft an HTML page that, when loaded by an authenticated victim, submits a POST request to `/account/email` with the attacker's email address. The victim's browser sends their authentication cookie automatically, but there is no CSRF token to validate, so the server accepts the request and changes the victim's email address.

## Fix
Inject `IAntiforgery` into the endpoint handler and call `ValidateRequestAsync()` before processing the email update:

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
ASP.NET Core's antiforgery middleware (`app.UseAntiforgery()`) is configured but does not automatically validate CSRF tokens on minimal API endpoints. The handler must explicitly call `IAntiforgery.ValidateRequestAsync(context)` to validate the request's CSRF token before processing any state-changing operation.

The validation call will throw an `InvalidOperationException` if the token is missing or invalid, which ASP.NET Core's exception handling converts to an HTTP 400 response, preventing the state change. Legitimate requests from the same origin (which include the CSRF token in headers or form data) pass validation; cross-origin attacker requests fail because they cannot read or submit the token.

The injection of `IAntiforgery` as a parameter is resolved by ASP.NET Core's dependency injection container, and the validation must occur before the `UpdateEmailAsync()` call to ensure every state-changing request is protected.
