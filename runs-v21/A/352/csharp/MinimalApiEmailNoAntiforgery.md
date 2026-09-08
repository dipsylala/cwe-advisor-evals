## Verdict
Confirmed CSRF vulnerability. The endpoint accepts POST requests to change email but lacks CSRF token validation.

## Source
The POST endpoint at `/account/email` in EmailEndpoints.cs (line 7) changes sensitive user data (email address) without validating an antiforgery token. While the application registers antiforgery services in Program.cs, the middleware is not invoked, leaving the endpoint unprotected against cross-site request forgery attacks.

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

## Explanation
The vulnerability exists because the antiforgery middleware is not enabled. Adding `app.UseAntiforgery()` after the authorization middleware ensures that all POST, PUT, PATCH, and DELETE requests are validated against CSRF tokens. This forces the endpoint to require a valid antiforgery token, which cannot be forged by an attacker from another site. The token is scoped to the user's session and cannot be obtained cross-origin due to same-origin policy restrictions.
