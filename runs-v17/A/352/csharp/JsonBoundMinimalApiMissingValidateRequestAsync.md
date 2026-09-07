## Verdict
CONFIRMED. The minimal API endpoint handles a state-changing POST request (email change) with authentication but does not validate the antiforgery token, leaving it open to CSRF attacks.

## Source
The vulnerable code is in the `MapPost` endpoint handler for `/account/email`. Although `app.UseAntiforgery()` is configured, ASP.NET Core's antiforgery middleware does not automatically validate tokens for JSON-bound minimal API endpoints. The endpoint accepts a JSON request body (`EmailChangeRequest`) and processes it without explicit token validation.

## Fix
Inject `IAntiforgery` into the endpoint handler and call `ValidateRequestAsync(context)` at the start of the handler before processing the request. This explicitly validates the CSRF token for the JSON POST request.

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
    await antiforgery.ValidateRequestAsync(context);
    
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

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
ASP.NET Core's antiforgery middleware automatically validates tokens for traditional form-based requests but not for JSON-bound minimal API endpoints. When an endpoint accepts JSON and modifies state, explicit token validation is required.

The fix adds `IAntiforgery` as a parameter to the handler (dependency injection), which provides access to the validation method. Calling `ValidateRequestAsync(context)` early in the handler ensures the request includes a valid antiforgery token before any state-changing operations occur. If the token is missing or invalid, the method throws an `AntiforgeryValidationException`, preventing the unauthorized state change.
