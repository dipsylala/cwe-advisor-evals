## Verdict

Exploitable. The minimal API endpoint at line 7 accepts POST requests that modify state without validating CSRF tokens. While the endpoint requires authentication, an authenticated attacker can craft a request (via HTML form or JavaScript on a malicious site) to change the victim's email address, exploiting the trust relationship between the victim's browser and the application.

## Source

An attacker-controlled POST request to `/account/email` containing a malicious email address in the JSON body. The attack surface is available to any authenticated user whose session cookie is present in the browser when visiting an attacker-controlled page.

## Fix

**Program.cs** – Add `app.UseAntiforgery()` to the middleware pipeline after authentication and authorization:

```csharp
using Cases.Csrf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();  // Add this line

EmailEndpoints.Map(app);

app.Run();
```

**EmailEndpoints.cs** – Inject `IAntiforgery` and validate the CSRF token before processing the request:

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

The fix adds anti-forgery token validation in two places. First, `app.UseAntiforgery()` is inserted into the middleware pipeline after authentication and authorization, enabling the framework's token generation and validation infrastructure. Second, since this endpoint binds JSON (not form data), the middleware alone does not enforce token validation on JSON-bound endpoints—the check is recorded but not enforced. Therefore, `IAntiforgery` is injected into the handler and `await antiforgery.ValidateRequestAsync(context)` is called before processing the email change request. This ensures the endpoint rejects requests lacking a valid anti-forgery token in the `RequestVerificationToken` header, preventing CSRF attacks while preserving the original functionality for legitimate requests carrying valid tokens.

## Behaviour changes

- **Added parameter**: `HttpContext context` and `IAntiforgery antiforgery` are now injected into the handler. The framework resolves these automatically from dependency injection; no breaking change to callers.
- **Added call**: `await antiforgery.ValidateRequestAsync(context)` will throw `AntiforgeryValidationException` if the token is missing or invalid, causing the endpoint to return a 400 Bad Request response before the email change is queued. This is the intended security behavior—legitimate clients must provide the token in the `RequestVerificationToken` header.
- **Middleware addition**: `app.UseAntiforgery()` in Program.cs generates and validates tokens for all endpoints in the pipeline, with no visible change to endpoint contracts.
