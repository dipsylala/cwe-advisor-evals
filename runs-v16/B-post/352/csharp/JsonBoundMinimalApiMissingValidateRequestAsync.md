## Verdict

Exploitable. The endpoint accepts authenticated POST requests to perform state-changing operations (email modification) without verifying CSRF tokens. An attacker can exploit a logged-in user's active session to forge unauthorized email changes.

## Source

User-supplied email address from JSON request body: `EmailChangeRequest.NewEmail` parameter at line 18. The parameter is bound directly from the HTTP POST body without CSRF validation.

## Fix

**Vulnerable code (lines 18-29):**
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

The vulnerability occurs because ASP.NET Core's `app.UseAntiforgery()` middleware does not auto-validate CSRF tokens for minimal API endpoints that bind their request body from JSON. While the middleware is correctly installed (line 16), it silently skips validation when it encounters a JSON-bound endpoint. The fix injects the `IAntiforgery` service into the handler and explicitly calls `await antiforgery.ValidateRequestAsync(context)` at the start of request processing, before any state-changing operation. This forces validation of the CSRF token in the request header (`RequestVerificationToken` by default) against the server-bound token in the antiforgery cookie. The validation will throw `AntiforgeryValidationException` if the token is missing or invalid, preventing the unauthorized action.

## Behaviour changes

**New parameter:** `IAntiforgery antiforgery` is injected by the dependency injection container. ASP.NET Core's built-in DI automatically resolves this from `builder.Services.AddAntiforgery()` (line 9) with no additional configuration required.

**New behavior:** `await antiforgery.ValidateRequestAsync(context)` is called before processing the request. This call is asynchronous and will throw `AntiforgeryValidationException` if the CSRF token is missing or does not match the server-bound token. The exception is handled by the framework's error middleware, returning an HTTP 400 Bad Request response. Clients must now include the antiforgery token in a request header named `RequestVerificationToken` (or a custom header name if configured via `AntiforgeryOptions.HeaderName`).

**Preserved behavior:** The sink contract (`UpdateEmailAsync`) is unchanged. The method still receives the same `userId` and `newEmail` parameters. The authorization check still requires an authenticated user. The response remains `Results.Accepted()` on success.

## Verification

Compiled with `dotnet build` targeting .NET 8.0 on the fixed code in isolation. Build succeeded with 0 warnings and 0 errors, confirming correct syntax and API availability.

## Assumptions

- The endpoint is intended to accept JSON-formatted requests (implied by the `EmailChangeRequest` parameter binding from the body), not form data or query strings. The fix assumes clients will supply the CSRF token via the `RequestVerificationToken` header, which is the standard mechanism for JSON APIs in ASP.NET Core.
- The `IAntiforgery` service is available because `builder.Services.AddAntiforgery()` is already called in the startup configuration (line 9). No additional dependency configuration is required.

## Confidence

High. The data flow is clear (JSON body → `request.NewEmail` → `UpdateEmailAsync`), the C# guidance explicitly addresses this exact pattern (JSON-bound minimal APIs), and the fix is framework-provided with standard API contracts. The compiled verification confirms no syntax or signature errors.
