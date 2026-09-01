## Verdict

CSRF protection is incomplete. The antiforgery service is registered but the middleware is not enabled, leaving the email-change endpoint vulnerable to cross-site request forgery attacks.

## Source

**EmailEndpoints.cs, line 7:** The POST endpoint mapping does not enforce CSRF token validation.

**Program.cs, line 4:** Antiforgery service is registered with `AddAntiforgery()`, but line 4 does not include the required middleware to validate tokens on incoming requests.

## Fix

**Program.cs:**
Add the antiforgery middleware. Insert `app.UseAntiforgery();` after `app.UseAuthorization();` (between lines 8 and 9):

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

No change is required to **EmailEndpoints.cs**. Once the middleware is active, ASP.NET Core automatically validates CSRF tokens for POST requests that are not explicitly exempted.

## Explanation

ASP.NET Core's antiforgery system requires two components: service registration and middleware activation. Registering the service without the middleware leaves the application vulnerable because tokens are never validated on incoming requests.

The `.UseAntiforgery()` middleware must be called before endpoints are mapped to ensure all POST requests to protected endpoints carry a valid antiforgery token. By placing it after authorization but before route mapping, the middleware intercepts state-changing requests and enforces token validation.

The endpoint at line 7 performs a sensitive operation (changing the user's email) and requires authentication, but authentication alone does not prevent CSRF attacks. A browser-based attacker can forge a request from a malicious site if the victim is already authenticated and no token validation occurs. The antiforgery middleware closes this gap by requiring an unpredictable token that the malicious site cannot obtain.
