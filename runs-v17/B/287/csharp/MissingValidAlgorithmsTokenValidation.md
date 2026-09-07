## Verdict

Exploitable. The `TokenValidationParameters` on line 15 omits `ValidAlgorithms`, leaving the accepted signing algorithm decided by key type rather than pinned server-side. An attacker can forge a JWT signed with a different algorithm (e.g., `HS256` when the issuer uses `RS256`, or `alg: none`) and if the framework or application code does not enforce the expected algorithm, the forged token may be accepted.

## Source

Configuration of JWT bearer authentication in `Program.cs`, line 15: `TokenValidationParameters` is instantiated without `ValidAlgorithms`.

## Fix

### File: Program.cs

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Targets .NET 8's JwtBearer handler (Microsoft.AspNetCore.Authentication.JwtBearer 8.x),
// which validates via JsonWebTokenHandler under the TokenValidationParameters configured below.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var signingKeyBytes = Convert.FromBase64String(
            builder.Configuration["Jwt:SigningKey"]!);

        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/account/balance", (HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    return Results.Ok(new { userId, balance = 1000 });
}).RequireAuthorization();

app.Run();
```

## Explanation

The fix adds `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }` to the `TokenValidationParameters` configuration. This pins the accepted signing algorithm to HMAC SHA256, which matches the `SymmetricSecurityKey` key type used here. By explicitly setting `ValidAlgorithms`, the JWT bearer middleware will reject any token signed with a different algorithm, preventing algorithm-confusion and algorithm-substitution attacks where an attacker could forge a token with a weaker or no-signature algorithm and have it accepted. The fix enforces server-side control over which algorithms are trusted, closing CWE-287.

## Behaviour changes

Added `ValidAlgorithms` property to `TokenValidationParameters` initializer (line 24). This is a mandatory security configuration that changes token validation behavior: tokens not signed with the explicitly allowed algorithm(s) will now be rejected during JWT validation. This is the correct and intended behavior to prevent authentication bypass and has no negative side effects on legitimate tokens signed by the intended issuer with the correct algorithm.
