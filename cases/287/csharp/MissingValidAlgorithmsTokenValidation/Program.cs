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
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes)
            // No ValidAlgorithms set: the accepted signing algorithm(s) are left to whatever
            // the resolved key type supports, rather than pinned to what the issuer signs with.
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
