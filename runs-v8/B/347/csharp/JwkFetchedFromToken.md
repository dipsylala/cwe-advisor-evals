## Verdict

Real. An attacker can forge JWTs by providing a `jku` header pointing to their own JWKS, then signing the token with their own key. The verifier fetches and trusts that attacker-controlled key to validate the signature.

## Source

`jwt.Header["jku"]` at line 25: the `jku` (JSON Web Key URL) claim is read directly from the untrusted JWT header.

## Fix

Remove the `IssuerSigningKeyResolver` that reads the token header. Fetch the JWKS from a trusted, server-controlled URL and set `IssuerSigningKeys` from that trusted source. Add `ValidAlgorithms` to restrict accepted signature algorithms.

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
        // Fetch JWKS from a hardcoded, server-controlled URL only
        _trustedKeySet = JsonWebKeySetFetcher.Fetch("https://auth.example.com/.well-known/jwks.json");
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

The vulnerability exists because the original code delegates key selection to an `IssuerSigningKeyResolver` that reads the `jku` header from the untrusted token and fetches the key from that URL. This gives the attacker control over which key is used to verify their own signature.

The fix establishes a hard boundary: the verification key comes from server configuration only. The JWKS is fetched once at initialization from a hardcoded trusted URL (`https://auth.example.com/.well-known/jwks.json`), not from the token. The resolver is removed entirely. Additionally, `ValidAlgorithms` is set to an explicit allowlist (`RsaSha256`) to prevent algorithm-confusion attacks where an attacker switches from RS256 to HS256.

## Behaviour changes

- **JWKS fetching moves from per-validation to initialization**: The JWKS is fetched once when the validator is constructed, not on every token validation. This improves performance but requires JWKS rotation to be handled via re-instantiation or periodic refresh of `_trustedKeySet`.
- **Exceptions on JWKS fetch now happen at construction time**: If the JWKS URL is unreachable or invalid, an exception is raised when the validator is created, not when a token is validated. Handle this in the code that instantiates the validator.
- **Tokens signed by unintended issuers are now rejected**: Only keys from the hardcoded JWKS are trusted. Tokens signed by issuers whose keys are not in that JWKS will be rejected with `SecurityTokenSignatureKeyNotFoundException`.
