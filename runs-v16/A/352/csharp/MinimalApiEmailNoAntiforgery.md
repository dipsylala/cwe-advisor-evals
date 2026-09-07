## Verdict

CSRF vulnerability confirmed. The POST endpoint for changing the user's email lacks antiforgery token validation despite the service being registered.

## Source

**EmailEndpoints.cs, line 7:**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

The endpoint accepts a POST request to change the user's email and requires authorization, but does not validate an antiforgery token. An attacker can craft a malicious page that, when visited by an authenticated user, submits a forged request to change the user's email address.

**Program.cs shows the gap:**
- Line 4: `builder.Services.AddAntiforgery()` registers the antiforgery service
- Missing: No `app.UseAntiforgery()` middleware call
- Missing: No antiforgery token validation on the endpoint

## Fix

**Program.cs** - Add the antiforgery middleware:
```csharp
using Cases.Csrf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAntiforgery();  // Add this line
app.UseAuthentication();
app.UseAuthorization();

EmailEndpoints.Map(app);

app.Run();
```

**EmailEndpoints.cs** - Add antiforgery token validation to the endpoint:
```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
        {
            await service.QueueAsync(request.Email);
            return Results.Accepted();
        }).RequireAuthorization()
          .WithAntiforgeryToken();  // Add this line
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

ASP.NET Core's antiforgery protection requires two components: (1) middleware to validate tokens on incoming requests, and (2) token validation on the endpoint itself.

**Why the vulnerability exists:**
- The antiforgery service is registered but the middleware is never activated, so no tokens are validated on any request
- The endpoint lacks the `.WithAntiforgeryToken()` call, meaning even if middleware were active, this endpoint would not require a token

**Why the fix works:**
- `app.UseAntiforgery()` activates the antiforgery middleware, which validates incoming tokens and fails any request without a valid token
- `.WithAntiforgeryToken()` on the endpoint explicitly declares that this POST endpoint requires an antiforgery token
- Together, these prevent forged requests: an attacker's malicious page cannot obtain or send a valid token for the user's session

**Minimal Apis antiforgery pattern:**
In Minimal APIs, the `.WithAntiforgeryToken()` method marks an endpoint as requiring antiforgery validation. When used with `UseAntiforgery()` middleware, it ensures only same-origin, token-bearing requests succeed.
