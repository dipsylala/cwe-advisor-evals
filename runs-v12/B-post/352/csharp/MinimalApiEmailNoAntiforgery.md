## Verdict

**VULNERABLE:** The POST endpoint at `/account/email` lacks CSRF token validation. Although it has `.RequireAuthorization()`, this only checks whether the user is authenticated, not whether the request originates from the application. An attacker can craft a malicious page that forces an authenticated user to send a request to this endpoint, changing their email address without consent.

## Source

The vulnerable endpoint in `EmailEndpoints.cs` (lines 7-11):

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

This is a minimal API endpoint that processes state-changing operations (email change) without verifying the request's authenticity. Because it binds `EmailChangeRequest` from the request body (JSON binding, not form binding), the standard `app.UseAntiforgery()` middleware alone does not enforce token validation—it only validates form-bound endpoints. Explicit `IAntiforgery` injection and validation is required.

## Fix

```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service, Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery, HttpContext context) =>
        {
            await antiforgery.ValidateRequestAsync(context);
            await service.QueueAsync(request.Email);
            return Results.Accepted();
        }).RequireAuthorization();
    }
}

public sealed record EmailChangeRequest(string Email);

public sealed class EmailChangeService
{
    public System.Threading.Tasks.Task QueueAsync(string email)
    {
        return System.Threading.Tasks.Task.CompletedTask;
    }
}
```

**Configuration requirement:** The application's startup code must call `services.AddAntiforgery()` in `ConfigureServices` and `app.UseAntiforgery()` in the middleware pipeline (after authentication/authorization, before endpoints). The middleware generates and validates tokens; the manual `ValidateRequestAsync` call enforces validation for this JSON-bound endpoint.

## Explanation

ASP.NET Core's CSRF protection uses the Synchronizer Token Pattern: a server-generated token is bound to the user's session and must be included in requests that modify state. Tokens are validated server-side before processing.

For minimal APIs that bind JSON (not forms), `app.UseAntiforgery()` middleware records validation results but does not enforce rejection. The fix injects `IAntiforgery` and calls `await antiforgery.ValidateRequestAsync(context)` to enforce the check before processing the request. This call:

1. Retrieves the token from the standard `RequestVerificationToken` header or cookie
2. Verifies the token is valid and bound to the authenticated user
3. Throws `AntiforgeryValidationException` if validation fails, preventing the state change

The injected `HttpContext` is passed to the validation method so it can access the token from headers/cookies and the authenticated user's identity.

## Behaviour changes

- **Before fix:** Requests lacking a valid CSRF token are processed, allowing cross-site attackers to force email changes.
- **After fix:** Requests lacking a valid CSRF token are rejected with an HTTP 400 (Bad Request) error. Only requests carrying a valid token (from the same origin) proceed to the handler. Legitimate clients (the web application's own forms/AJAX) must include the token in the `RequestVerificationToken` header for JSON-bound requests, or in form data for form-bound requests.
- **Client impact:** If email-change requests are made via JavaScript, the client must:
  1. Retrieve the token from the response HTML or a dedicated token endpoint
  2. Include it in the `RequestVerificationToken` request header on every POST to `/account/email`
  3. Requests from malicious cross-origin pages will be rejected even if the user is authenticated
