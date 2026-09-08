## Verdict

Confirmed: CWE-352 (Cross-Site Request Forgery). The JSON-bound minimal API endpoint accepts POST requests without explicitly validating the CSRF token.

## Source

The vulnerable endpoint at line 18 is a POST handler that binds its request body from JSON (`EmailChangeRequest request`). It authenticates the user and then performs a state-changing operation (UpdateEmailAsync) without validating a CSRF token. While `app.UseAntiforgery()` is present in the middleware pipeline, it only auto-validates form-bound endpoints; JSON-bound endpoints must call `ValidateRequestAsync()` explicitly to enforce the check.

## Fix

### File: Program.cs

```csharp
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
builder.Services.AddScoped<AccountService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context, IAntiforgery antiforgery) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await antiforgery.ValidateRequestAsync(context);

    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();

app.Run();

public record EmailChangeRequest(string NewEmail);

public class AccountService
{
    public Task UpdateEmailAsync(string userId, string newEmail)
    {
        Console.WriteLine($"Updating email for {userId} to {newEmail}");
        return Task.CompletedTask;
    }
}
```

## Explanation

The fix adds two key elements:

1. **Inject IAntiforgery service**: The endpoint handler now includes `IAntiforgery antiforgery` as a parameter, which ASP.NET Core's dependency injection automatically provides.

2. **Validate the request**: Before processing the state-changing operation, `await antiforgery.ValidateRequestAsync(context)` is called. This enforces CSRF token validation for JSON-bound endpoints by checking for a valid token in the request headers (the default header name is `RequestVerificationToken`).

For JSON API endpoints, clients must include the token in a request header with the configured name (default: `RequestVerificationToken`). The validation fails and raises an exception if the token is missing or invalid, preventing CSRF attacks.
