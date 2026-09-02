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

app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

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
