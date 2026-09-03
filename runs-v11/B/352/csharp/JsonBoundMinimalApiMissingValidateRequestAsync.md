## Verdict

Confirmed. The minimal API endpoint accepts JSON-bound request data and performs a state-changing operation without explicit CSRF token validation. Although `app.UseAntiforgery()` is configured in the middleware pipeline, ASP.NET Core's anti-forgery middleware does not enforce validation for JSON-bound endpoints — it only auto-validates endpoints that bind form data. This allows CSRF attacks to succeed.

## Source

**File:** Program.cs, lines 18–29
**Handler:** `app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context) => { ... })`
**Operation:** Line 27, `await accounts.UpdateEmailAsync(userId, request.NewEmail);`

The endpoint:
- Requires authentication via `.RequireAuthorization()`
- Binds the request body from JSON (`EmailChangeRequest request`)
- Modifies application state (updates user email)
- Does not validate an anti-forgery token before processing the request

## Fix

Inject `IAntiforgery` into the handler and call `await antiforgery.ValidateRequestAsync(context)` before processing the email update:

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

Changes:
- Add `IAntiforgery antiforgery` parameter to the handler signature (line 18)
- Add `await antiforgery.ValidateRequestAsync(context);` before the `UpdateEmailAsync` call (new line before the original line 27)

## Explanation

ASP.NET Core's `app.UseAntiforgery()` middleware automatically validates form-bound requests but skips enforcement for JSON-bound endpoints. When a minimal API handler binds its body from JSON (rather than `IFormCollection` or `[FromForm]`), the middleware records that validation was attempted but does not reject the request if the token is missing or invalid.

The CWE-352 C# guidance states: "For a JSON-bound minimal API endpoint, inject `IAntiforgery` and call `await antiforgery.ValidateRequestAsync(context)` at the top of the handler to enforce the header-token check."

Calling `ValidateRequestAsync` explicitly enforces the check before the state-changing operation proceeds. The framework's `IAntiforgery` service validates the request-header token (defaulting to the header name `RequestVerificationToken`) against the token bound to the authenticated user's session, using constant-time comparison.

## Behaviour changes

- **Before:** POST requests to `/account/email` are accepted from any origin, including cross-origin requests forged by an attacker's site. An attacker can change the authenticated user's email.
- **After:** POST requests to `/account/email` are rejected if they omit the anti-forgery token header or supply an invalid token. The handler only proceeds if the token is valid and bound to the authenticated user's session. Legitimate cross-origin requests (if needed) must include the token in the `RequestVerificationToken` header.
- **Client impact:** Any client making requests to this endpoint must extract the CSRF token from a safe location (e.g., a form field or endpoint response) and include it in the `RequestVerificationToken` request header.
