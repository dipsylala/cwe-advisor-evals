using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace EvalCases;

public class ReportTokenValidator
{
    public ClaimsPrincipal ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://auth.example.com",
            ValidateAudience = true,
            ValidAudience = "api://reports",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
            {
                var jwt = (JwtSecurityToken)securityToken;
                var jku = jwt.Header["jku"]?.ToString();
                var keySet = JsonWebKeySetFetcher.Fetch(jku);
                return keySet.Keys.Where(k => k.KeyId == kid);
            }
        };

        // SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
        return handler.ValidateToken(token, parameters, out _);
    }
}
