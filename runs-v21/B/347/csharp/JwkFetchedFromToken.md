## Verdict
CONFIRMED. The code fetches JWT verification keys from a URL specified in the untrusted JWT header (`jku`), violating the requirement that verification keys must come from trusted, application-controlled sources only.

## Source
The vulnerability is in the `IssuerSigningKeyResolver` callback (lines 22-28), which:
1. Reads the `jku` claim from the JWT header without validation
2. Fetches a key set from this untrusted URL
3. Uses keys from that URL to verify the token's signature

An attacker can craft a JWT with a malicious `jku` URL pointing to a server hosting keys they control, bypassing signature verification entirely.

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
    private readonly JsonWebKeySet _trustedKeySet;
    
    public ReportTokenValidator()
    {
        // Fetch JWKS from a trusted, hardcoded application-controlled URL only
        var trustedJwksUrl = "https://auth.example.com/.well-known/jwks.json";
        _trustedKeySet = JsonWebKeySetFetcher.Fetch(trustedJwksUrl);
    }

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
            IssuerSigningKeys = _trustedKeySet.Keys,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

## Explanation
The fix moves JWKS fetching from dynamic, token-header-driven to static, application-controlled:

1. **Removed the `IssuerSigningKeyResolver` callback** that read the untrusted `jku` header and fetched keys from it. This resolver was the attack surface.

2. **Moved JWKS fetching to the constructor** from a hardcoded, trusted URL (`https://auth.example.com/.well-known/jwks.json`). This URL is now under application control, not attacker control.

3. **Set `IssuerSigningKeys` to the pre-fetched trusted keys** instead of retrieving them dynamically based on token content.

4. **Added `ValidAlgorithms`** to restrict token verification to RSA-SHA256, preventing algorithm confusion attacks.

This ensures verification keys come from a trusted, application-controlled source as required by CWE-347 remediation guidance. The attacker can no longer direct the validator to arbitrary JWKS endpoints.

## Behaviour changes
- JWKS is now fetched once at validator initialization rather than per token. This improves performance but requires JWKS refresh logic if key rotation is needed (e.g., periodic re-fetch or event-driven refresh).
- The validator no longer accepts JWTs signed with algorithms other than RS256 (previously all algorithms the token declared were accepted if keys matched).
- JWTs with `jku` headers pointing to attacker-controlled URLs are now rejected because the signature cannot be verified with the trusted, pre-fetched keys.
