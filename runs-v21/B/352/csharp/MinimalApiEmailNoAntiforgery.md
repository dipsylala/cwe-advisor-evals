## Verdict

Exploitable. The POST endpoint at line 7 of EmailEndpoints.cs processes email changes without validating an anti-forgery token. An attacker can craft a malicious request that an authenticated user's browser submits without their knowledge, forcing an unwanted email change.

## Source

Attacker-controlled POST request body sent to `/account/email` endpoint with a JSON payload containing a malicious email address.

## Fix

**Root cause:** The application registers the anti-forgery service (`AddAntiforgery()`) but does not enable the middleware, and the endpoint handler does not validate the CSRF token before processing the request.

For minimal API endpoints that bind from JSON, the framework's `app.UseAntiforgery()` middleware alone is insufficient — the handler must explicitly call `ValidateRequestAsync()` to reject requests with missing or invalid tokens. Additionally, the middleware must be present in the pipeline.

### File: Program.cs

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

### File: EmailEndpoints.cs

```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service, HttpContext context, IAntiforgery antiforgery) =>
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

## Explanation

The fix adds anti-forgery protection to a state-changing minimal API endpoint that binds from JSON. 

In Program.cs, `app.UseAntiforgery()` is added after authorization middleware to enable the anti-forgery middleware pipeline.

In EmailEndpoints.cs, two parameters are injected into the handler: `HttpContext` (to provide request context) and `IAntiforgery` (the anti-forgery validation service registered by `AddAntiforgery()`). The handler calls `await antiforgery.ValidateRequestAsync(context)` at the start of the handler, before processing the email change. This call:
- Reads the anti-forgery token from the request (via the `RequestVerificationToken` header for JSON requests, or form data for form-encoded requests)
- Validates the token against the server-side token bound to the authenticated session
- Raises an exception if the token is missing or invalid, causing the request to fail

The framework's `ValidateRequestAsync` performs constant-time comparison using `CryptographicOperations.FixedTimeEquals` and validates the token is bound to the current user's claims.

## Behaviour changes

**Token requirement:** Callers must now supply a valid anti-forgery token in the `RequestVerificationToken` header (for JSON clients) or form field (for form-encoded clients). Requests without a valid token will be rejected with a 400 Bad Request before the handler executes.

**No other changes:** The response shape, status code, and service invocation remain unchanged for valid requests. The `RequireAuthorization()` and successful email queueing behavior is preserved.

