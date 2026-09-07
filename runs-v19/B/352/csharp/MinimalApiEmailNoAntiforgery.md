## Verdict

CONFIRMED: The minimal API endpoint `MapPost("/account/email", ...)` at EmailEndpoints.cs:7 accepts state-changing POST requests without CSRF token validation. The handler binds its request body from JSON, which bypasses the automatic token check that would apply to form-bound endpoints. The middleware `app.UseAntiforgery()` is also absent from the pipeline.

## Source

**File:** EmailEndpoints.cs, lines 7–11

**State-changing endpoint without token validation:**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

**Supporting file:** Program.cs is missing `app.UseAntiforgery()` in the middleware pipeline.

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

## Explanation

The fix implements CSRF token validation on the minimal API endpoint by:

1. **Adding middleware:** `app.UseAntiforgery()` in Program.cs inserts the antiforgery middleware into the pipeline after authentication and authorization. This validates tokens for form-bound endpoints automatically.

2. **Explicit validation for JSON-bound handler:** Since the email endpoint binds its body from JSON (not form data), the middleware does not automatically enforce token validation. The fix injects `IAntiforgery` into the handler and calls `await antiforgery.ValidateRequestAsync(context)` at the start of the handler, before any state change occurs. The `ValidateRequestAsync` call will throw an exception if the token is missing or invalid, preventing the email change from processing.

The token is expected in the default header name `RequestVerificationToken` (no leading `X-`), which the framework's `AntiforgeryOptions` sets by default. Clients must include this header or the request will be rejected.

## Behaviour changes

- Authenticated requests to `POST /account/email` without a valid CSRF token will now be rejected with a 400 Bad Request (before: accepted).
- Legitimate requests must include the CSRF token in a header named `RequestVerificationToken`.
- No change to successful requests that include a valid token; the email queue behavior remains identical.
