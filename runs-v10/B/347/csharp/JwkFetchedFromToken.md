## Verdict

The finding is confirmed. The code trusts the `jku` (JWK Set URL) claim embedded in the JWT token header to fetch the signing key. Since JWT headers are part of the unsigned token payload, an attacker can supply a malicious `jku` value pointing to their own key server, sign a forged token with their own key, and bypass signature verification entirely. This violates CWE-347 by accepting keys from an untrusted source rather than validating against a pre-configured trust anchor.

## Source

The vulnerability originates in the `IssuerSigningKeyResolver` callback at lines 22-28. The resolver extracts the `jku` value directly from the untrusted token header and passes it to `JsonWebKeySetFetcher.Fetch(jku)`, which fetches the key set from an attacker-controlled URL. The sink is the `handler.ValidateToken()` call at line 32, which uses these fetched keys to validate the token's signature.

## Fix

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace EvalCases;

public class ReportTokenValidator
{
    private readonly string _trustedJwksUri = "https://auth.example.com/.well-known/openid-configuration/jwks";

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
            IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
            {
                // Fetch keys from server-controlled JWKS endpoint only
                var keySet = JsonWebKeySetFetcher.Fetch(_trustedJwksUri);
                return keySet.Keys.Where(k => k.KeyId == kid);
            }
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

## Explanation

The fix eliminates the vulnerability by:

1. **Removing dependency on untrusted header values**: The `jku` value from the token header is no longer read. Instead, the signing key is fetched from a hardcoded, server-controlled JWKS endpoint (`_trustedJwksUri`), ensuring the application controls which key server it trusts.

2. **Adding algorithm validation**: `ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }` restricts accepted algorithms to RS256 only, closing a secondary CWE-347 gap where an attacker could request algorithm downgrade (for example, switching from RS256 to HS256 and signing with the public key as an HMAC secret).

3. **Maintaining key resolution by kid**: The resolver still looks up the key by `kid` (key ID) from the trusted key set, allowing for key rotation and multiple signing keys without changing the resolver logic.

The fix follows the CWE-347 guidance: "Fix the key before reading the token: the verification key comes from configuration, a keystore, or a JWKS cache the application fetched, never from the token."

## Behaviour changes

- **Key Source**: Changed from attacker-controlled JWKS endpoint (via token header `jku`) to application-controlled trusted JWKS URI. Tokens signed with keys not in the trusted JWKS will now be rejected.
- **Algorithm Enforcement**: Added explicit algorithm validation. Tokens using algorithms other than RS256 will now be rejected, where previously any algorithm the library accepted would have been allowed.
- **Error Handling**: No change. Tokens with invalid signatures or mismatched key IDs continue to raise `SecurityTokenInvalidSignatureException` or `SecurityTokenSignatureKeyNotFoundException`.
- **Performance**: Added a dependency on fetching the trusted JWKS endpoint (this should typically be cached in `JsonWebKeySetFetcher`), but eliminates fetching from untrusted endpoints for every validation.
