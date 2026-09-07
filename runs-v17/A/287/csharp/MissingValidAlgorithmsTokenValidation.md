## Verdict
Confirmed. The `TokenValidationParameters` configuration lacks explicit `ValidAlgorithms` restriction, allowing any algorithm supported by the key type to be accepted during JWT validation. This bypasses a critical authentication control by permitting algorithm substitution attacks.

## Source
File: Program.cs, lines 15–26.

The `TokenValidationParameters` object configures JWT validation for the JwtBearer authentication handler. The missing `ValidAlgorithms` property leaves the accepted signing algorithms unconstrained, which violates CWE-287's requirement to authenticate by validating cryptographic signatures against a known and restricted set of algorithms.

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
The fix adds `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }` to explicitly pin the accepted signing algorithm to HMAC-SHA256, which is the standard algorithm for symmetric keys (HS256 in JWT notation). This restricts the validation handler to reject any token signed with a different algorithm, closing the algorithm substitution attack vector.

The `SecurityAlgorithms.HmacSha256` constant is provided by `Microsoft.IdentityModel.Tokens`, already imported in the file. This explicit allowlist ensures that even if an attacker crafts a token using an unsupported algorithm, the validation handler will reject it as invalid rather than attempting to verify it with an unexpected mechanism.
