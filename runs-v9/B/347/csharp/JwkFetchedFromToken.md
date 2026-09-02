## Verdict

Exploitable. CWE-347 (Improper Verification of Cryptographic Signature), high confidence.

## Source

The `jku` (JWK Set URL) header of the JWT being validated: `jwt.Header["jku"]?.ToString()` inside the `IssuerSigningKeyResolver` (line 25). This header is part of the token under validation, so it is attacker-controlled - an attacker forging a token can set `jku` to a URL they host.

The tainted value flows into `JsonWebKeySetFetcher.Fetch(jku)` (line 26), which fetches a JWK set from that attacker-chosen URL, and the returned keys are filtered by `kid` (line 27) and handed back as the trusted signing key(s) for `handler.ValidateToken(token, parameters, out _)` (line 32, the reported sink).

## Fix

Vulnerable code (`JwkFetchedFromToken.cs`):

```csharp
var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://auth.example.com",
    ValidateAudience = true,
    ValidAudience = "api://reports",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    // VULNERABLE: the trust anchor is derived from the token's own "jku" header,
    // so an attacker can point it at a JWK set they control and sign the token themselves.
    IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
    {
        var jwt = (JwtSecurityToken)securityToken;
        var jku = jwt.Header["jku"]?.ToString();
        var keySet = JsonWebKeySetFetcher.Fetch(jku);
        return keySet.Keys.Where(k => k.KeyId == kid);
    }
};

return handler.ValidateToken(token, parameters, out _);
```

Fixed code:

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace EvalCases;

public class ReportTokenValidator
{
    // The JWKS location is part of the trusted issuer's own configuration, never derived
    // from the token being validated.
    private const string TrustedJwksUri = "https://auth.example.com/.well-known/jwks.json";

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
                // Keys are always fetched from the pinned, trusted JWKS endpoint - never
                // from a "jku" or any other header inside the unverified token.
                var keySet = JsonWebKeySetFetcher.Fetch(TrustedJwksUri);
                return keySet.Keys.Where(k => k.KeyId == kid);
            }
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

## Explanation

The resolver treated the token's own `jku` header as the source of truth for which key set to trust, so any attacker could mint a token, host a JWK set containing their own public key at a URL of their choosing, put that URL in `jku`, and sign the token with the matching private key - `ValidateToken()` would then successfully verify a signature the attacker fully controls. The fix removes the header read entirely and replaces it with a constant, pre-configured JWKS URI belonging to the trusted issuer (`https://auth.example.com`, the same issuer already pinned via `ValidIssuer`), so the set of keys eligible to satisfy `kid` lookup can never be influenced by the token being checked. `ValidAlgorithms` is also pinned to `RsaSha256`: the resolver now always returns an RSA public key, and without an explicit algorithm allowlist the handler would still accept a token whose header declares `HS256`, letting an attacker use that public RSA key bytes as an HMAC secret to forge a signature that validates - a second route to the same CWE-347 weakness that fixing the key source alone does not close.

## Behaviour changes

- `IssuerSigningKeyResolver` fetches from a fixed `TrustedJwksUri` instead of a URL read from the token's `jku` header, and no longer casts `securityToken` to `JwtSecurityToken` or reads its `Header` - required to remove the attacker-controlled trust anchor; the resolver's return shape (an `IEnumerable<SecurityKey>` filtered by `kid`) is unchanged, so all other resolver-consuming behaviour is preserved.
- `ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }` is newly set; previously unset, which defaults to accepting whatever algorithm the token's own header declares. This closes the RS256-to-HS256 confusion route described above. This narrows acceptance from "any algorithm" to RS256 only - a legitimate token signed with a different algorithm the issuer might use (e.g. RS384/RS512, if any are actually issued) would now be rejected; confirm the issuer's actual signing algorithm(s) and extend the array if more than RS256 is in use.
- All other `TokenValidationParameters` fields (`ValidateIssuer`, `ValidIssuer`, `ValidateAudience`, `ValidAudience`, `ValidateLifetime`, `ValidateIssuerSigningKey`) are unchanged. `handler.ValidateToken(token, parameters, out _)` still discards the `out SecurityToken` parameter and still returns a `ClaimsPrincipal` on success or throws a `SecurityTokenException` subtype on failure, exactly as before.
