## Verdict

The endpoint lacks explicit CSRF token validation. Although `services.AddAntiforgery()` is called during startup, the minimal API POST endpoint neither uses `app.UseAntiforgery()` middleware (which is required for minimal APIs) nor injects `IAntiforgery` to validate the request. The endpoint binds JSON request data, which means `app.UseAntiforgery()` alone would not enforce validation—explicit validation is required.

## Source

**File:** `E:/Github/cwe-advisor/evals/cases/352/csharp/MinimalApiEmailNoAntiforgery/EmailEndpoints.cs`

**Line:** 7 (the `app.MapPost` call)

**Root cause:** The POST endpoint accepts an authenticated state-changing request (changing email) without verifying a CSRF token. The application registers antiforgery services but does not enable the middleware or enforce token validation in the handler.

## Fix

Replace the `EmailEndpoints.cs` file:

```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (HttpContext context, EmailChangeRequest request, IAntiforgery antiforgery, EmailChangeService service) =>
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

Additionally, add `app.UseAntiforgery()` middleware in `Program.cs` after authentication/authorization:

```csharp
using Cases.Csrf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

EmailEndpoints.Map(app);

app.Run();
```

## Explanation

The fix addresses two layers of CSRF protection required for minimal APIs in ASP.NET Core:

1. **Middleware layer:** `app.UseAntiforgery()` must be added to the middleware pipeline, placed after authentication and authorization. This middleware prepares the request for validation.

2. **Handler layer:** Because the endpoint binds its body from JSON (the `EmailChangeRequest` record), `app.UseAntiforgery()` middleware alone does not enforce validation—it only records the check internally. For JSON-bound minimal API endpoints, explicit validation is required by injecting `IAntiforgery` and calling `await antiforgery.ValidateRequestAsync(context)` at the start of the handler.

The fix injects both `HttpContext` (needed to pass to the validation method) and `IAntiforgery` (the service performing the validation). The validation call:
- Extracts the CSRF token from the request header (defaulting to `RequestVerificationToken`)
- Compares it against the token bound to the authenticated user's session
- Throws `InvalidOperationException` if the token is missing or invalid, preventing the request from proceeding

This prevents cross-site attackers from forcing authenticated users to change their email address, since the attacker cannot obtain or predict the user's valid CSRF token.

## Behaviour changes

**Before:** An attacker could craft a cross-site request that changes the victim's email by exploiting the browser's automatic inclusion of the session cookie. The endpoint would process the request without verifying its authenticity.

**After:** 
- Requests originating from the authenticated application (forms, fetch calls with the token header) succeed if they include a valid token.
- Requests from cross-site origins fail with `InvalidOperationException` before the email change is processed, because they cannot obtain the server-controlled CSRF token.
- Legitimate users see no change in behavior—the application now properly validates all incoming email change requests against their session token.
