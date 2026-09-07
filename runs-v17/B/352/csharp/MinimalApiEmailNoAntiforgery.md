## Verdict

exploitable

## Source

HTTP POST request to `/account/email` endpoint from external origin (attacker-controlled via CSRF attack vector)

## Fix

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
        app.MapPost("/account/email", async (HttpContext context, EmailChangeRequest request, EmailChangeService service, IAntiforgery antiforgery) =>
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

The POST endpoint at line 7 of EmailEndpoints.cs accepts an authenticated request that performs a state-changing operation (email modification) without validating an antiforgery token. An attacker can exploit this by crafting a malicious cross-origin request that uses the victim's authenticated session to change their email address. The root causes are: (1) Program.cs registers antiforgery services but does not enable the `app.UseAntiforgery()` middleware, and (2) the minimal API endpoint does not explicitly validate antiforgery tokens. Since this endpoint binds its request body as JSON (`EmailChangeRequest`), middleware validation alone is insufficient—explicit token validation must be injected and called at the handler entry point.

The fix adds `app.UseAntiforgery()` to the middleware pipeline in Program.cs (after authentication and authorization) and injects the `IAntiforgery` service into the endpoint handler. The handler now calls `await antiforgery.ValidateRequestAsync(context)` before processing the email change request, enforcing token validation for all requests regardless of content type. This ensures the request originated from the application and was not forged by a cross-origin attacker.

## Behaviour changes

**Program.cs**:
- Added `app.UseAntiforgery()` call at line 9, placed after authorization middleware. This enables antiforgery middleware validation for minimal API endpoints and sets up the framework's token generation and validation infrastructure.

**EmailEndpoints.cs**:
- Added `HttpContext context` parameter to the endpoint handler. This parameter is required by the `IAntiforgery.ValidateRequestAsync()` method to access request headers and cookies.
- Added `IAntiforgery antiforgery` parameter to the endpoint handler. This injects the framework's antiforgery service, enabling token validation.
- Added `await antiforgery.ValidateRequestAsync(context);` call at line 10 (before `service.QueueAsync()`). This validates the antiforgery token in the request and throws an exception if the token is missing or invalid, preventing the email change from proceeding.

**Runtime behavior**: Requests to the endpoint must now include a valid `RequestVerificationToken` header (or cookie pair). Requests without a valid token will be rejected with an HTTP 400 Bad Request before the email is queued, preventing cross-origin forgery attacks.
