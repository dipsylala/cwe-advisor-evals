## Verdict

CONFIRMED

## Source

Line 15-26 in Program.cs configures `TokenValidationParameters` without restricting the algorithms accepted during JWT validation. The absence of `ValidAlgorithms` allows the handler to accept any algorithm supported by the key type (in this case, any HMAC variant for the symmetric key). This creates a vulnerability to algorithm substitution attacks, where an attacker could sign a forged token using an unintended algorithm.

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
            ValidAlgorithms = new[] { "HS256" }
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

The fix adds `ValidAlgorithms = new[] { "HS256" }` to the `TokenValidationParameters`. This explicit allowlist restricts the accepted signing algorithms to HS256 (HMAC-SHA256), preventing algorithm substitution attacks.

When `ValidAlgorithms` is not set, a JWT handler may accept tokens signed with algorithms the issuer does not use. For example, an attacker could sign a forged token using HS256 with a public key obtained from an asymmetric configuration, and if the handler falls back to supporting that algorithm, the forgery would validate incorrectly.

The HS256 algorithm is appropriate here because:
- A `SymmetricSecurityKey` uses symmetric algorithms (HMAC variants)
- HS256 is the standard choice for HMAC-based JWT signing
- The issuer must be configured to sign tokens with this same algorithm

If the issuer uses a different algorithm (HS384, HS512), the `ValidAlgorithms` array should match that exact algorithm. The configuration should enforce consistency between the issuer's signing algorithm and this allowlist, either by hardcoding the expected value or reading it from configuration in a way that cannot be subverted at runtime.
