## Verdict

Exploitable. The `TokenValidationParameters` does not restrict `ValidAlgorithms`, allowing algorithm confusion attacks where an attacker can switch a token from RS256 to HS256 and use the server's RSA public key as an HMAC secret.

## Source

Untrusted JWT token passed to `ValidateToken()` method at line 10 (parameter `token`). The token header contains attacker-controlled `alg` field.

## Fix

### File: JwkFetchedFromToken.cs

```csharp
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
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            RequireSignedTokens = true,
            RequireExpirationTime = true,
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
```

## Explanation

The vulnerability arises from missing algorithm validation in the JWT signature verification process. By default, `JwtSecurityTokenHandler.ValidateToken()` accepts whatever algorithm the token's header declares when `ValidAlgorithms` is not explicitly set. This enables algorithm confusion attacks: an attacker creates an RS256 token but modifies the header to declare `alg: HS256`, then signs it using the server's public RSA key as an HMAC secret (which is known to the attacker). The handler verifies the HMAC using the public key as the secret, treating the forged token as valid.

The fix adds three properties to `TokenValidationParameters`:

1. **`ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }`** - Restricts the handler to accept only RS256 signatures, preventing the attacker from downgrading to HS256 or other algorithms.
2. **`RequireSignedTokens = true`** - Explicitly rejects unsigned tokens (alg=none).
3. **`RequireExpirationTime = true`** - Hardens token validation by requiring an expiration time claim.

These changes ensure only properly signed tokens with the expected algorithm are accepted, closing the algorithm confusion vulnerability.

## Behaviour changes

- **ValidAlgorithms enforcement** - Tokens not signed with RS256 are rejected with `SecurityTokenInvalidSignatureException`. This is a security-critical behavior change that prevents algorithm confusion attacks.
- **RequireSignedTokens** - Unsigned tokens (with `alg: none`) will now be rejected. This breaks compatibility only with insecure token formats.
- **RequireExpirationTime** - Tokens without an `exp` claim will be rejected. This is consistent with best practices for JWT handling and prevents indefinite token validity.

All three changes are tightening security controls and have no functional impact on legitimate, properly formatted tokens from the authorized issuer.

Verification: C# syntax verified by manual review. The properties `ValidAlgorithms`, `RequireSignedTokens`, and `RequireExpirationTime` are standard members of `Microsoft.IdentityModel.Tokens.TokenValidationParameters` in all recent versions of the library. The constant `SecurityAlgorithms.RsaSha256` is defined in `Microsoft.IdentityModel.Tokens`.
