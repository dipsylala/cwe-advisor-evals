## Verdict

Exploitable. The POST endpoint at line 7 of EmailEndpoints.cs modifies account state (queues an email address change) without validating CSRF tokens. The application configures antiforgery services but does not enable the middleware, and the JSON-bound endpoint lacks explicit token validation required by ASP.NET Core's minimal API design.

## Source

Attacker-controlled POST request with JSON body sent from a malicious website to an authenticated victim's session at `/account/email`. The `EmailChangeRequest.Email` field is user-supplied without origin verification.

## Fix

**Program.cs** - Add the antiforgery middleware to the pipeline after authentication/authorization:

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();  // <-- ADD THIS LINE

EmailEndpoints.Map(app);

app.Run();
```

**EmailEndpoints.cs** - Inject `IAntiforgery` and validate the token before processing:

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

ASP.NET Core's minimal APIs do not run the legacy MVC filter `[ValidateAntiForgeryToken]` or `AutoValidateAntiforgeryTokenAttribute`, so the application must use `app.UseAntiforgery()` middleware instead. For JSON-bound endpoints (where the request body is deserialized to a CLR object), the middleware records the validation but does not enforce it—the endpoint must explicitly call `await antiforgery.ValidateRequestAsync(context)` to reject requests without a valid anti-forgery token. The fix adds both the middleware (which enforces validation for form-bound and simple-request endpoints) and the explicit handler-level call (which enforces it for JSON payloads). The token is bound to the authenticated user's session and compared in constant time by the framework's `CryptographicOperations.FixedTimeEquals`, closing the CSRF attack vector.

## Behaviour changes

- **HttpContext parameter added**: Required to pass context to `ValidateRequestAsync()`, following the minimal API dependency-injection pattern.
- **IAntiforgery parameter added**: Injected by the framework's service container; no user configuration needed.
- **ValidateRequestAsync() throws on token mismatch**: Requests without a valid token now raise an exception (converted to HTTP 400 Bad Request by default ASP.NET Core error handling), where the original endpoint accepted any request with a valid session. This is the intended behaviour change—rejecting unauthorized requests is the security fix.
- **Middleware ordering**: The middleware is placed after `UseAuthorization()` as specified in the guidance; this ensures the authenticated user's identity is available to bind the token validation to the session.
