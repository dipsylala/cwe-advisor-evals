## Verdict

VULNERABLE

The code allows an attacker to supply the URL where the signing key is fetched from via the `jku` header in the JWT. By crafting a token, signing it with their own key, and pointing `jku` to their own key server, an attacker can forge valid-looking tokens that pass all validation checks. Additionally, `ValidAlgorithms` is not set, permitting algorithm confusion attacks where HS256 is substituted for RS256.

## Source

The vulnerability is in the `IssuerSigningKeyResolver` callback (lines 22-28):

```csharp
IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
{
    var jwt = (JwtSecurityToken)securityToken;
    var jku = jwt.Header["jku"]?.ToString();
    var keySet = JsonWebKeySetFetcher.Fetch(jku);
    return keySet.Keys.Where(k => k.KeyId == kid);
}
```

The resolver accepts the `jku` (JWK Set URL) from the unverified token header and fetches keys from it. This inverts the trust decision: instead of the server deciding which issuer to trust, the token tells the server where to fetch the verification key from.

Additionally, `ValidAlgorithms` is not set in `TokenValidationParameters`, allowing an attacker to switch the algorithm from RS256 to HS256 and sign with the known RSA public key treated as an HMAC secret.

## Fix

Replace the `IssuerSigningKeyResolver` with a direct reference to signing keys fetched from a trusted, server-side URL. Set `ValidAlgorithms` to restrict acceptable algorithms:

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace EvalCases;

public class ReportTokenValidator
{
    private static readonly JsonWebKeySet TrustedKeySet = 
        JsonWebKeySetFetcher.Fetch("https://auth.example.com/.well-known/jwks.json");

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
            IssuerSigningKeys = TrustedKeySet.Keys,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

Key changes:
1. **Remove `IssuerSigningKeyResolver`**: Eliminates the logic that reads and uses the untrusted `jku` header.
2. **Fetch JWKS from a trusted URL**: The server fetches the key set from a known, trusted issuer URL (`https://auth.example.com/.well-known/jwks.json`), not from the token header.
3. **Set `IssuerSigningKeys`**: Populate this parameter directly with the trusted key set; the handler will match the token's `kid` against this set.
4. **Set `ValidAlgorithms`**: Explicitly restrict to `RsaSha256`, preventing algorithm confusion attacks.

## Explanation

**The vulnerability:** The original code treats the token as authoritative about where its signing key lives. An attacker can create a JWT, sign it with their own key, embed a `jku` URL pointing to their own key server, and the application will fetch and validate against the attacker's key. This completely bypasses signature verification.

**Why the fix works:**
- **Trust decision is server-controlled**: The application decides upfront which issuer (and therefore which JWKS URL) to trust. The token header cannot redirect key fetches.
- **Algorithm is not negotiable**: By setting `ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }`, the handler rejects any token claiming to use a different algorithm (e.g., HS256). This prevents algorithm confusion where an attacker switches RS256 to HMAC-SHA256 and signs with the known RSA public key as the HMAC secret.
- **Key matching is scoped**: The handler will only use keys from the trusted `IssuerSigningKeys` set; it will not accept keys from other sources or headers.

**Caching note**: The example caches `TrustedKeySet` as a static field. For production, implement periodic refresh (e.g., every 1 hour) or cache the keys with a TTL, since JWKS endpoints may rotate keys. A simple approach is to check if cached keys are stale on every token validation and refresh if needed.

## Behaviour changes

- **Tokens with untrusted issuer or algorithm**: Previously, if a `jku` header pointed to an attacker-controlled URL, the token would be accepted. Now, tokens are only accepted if signed with a key from the trusted, server-configured JWKS endpoint and use the approved algorithm (RS256).
- **Performance**: The JWKS is fetched once and cached, avoiding a network call per token validation. This improves performance compared to the original dynamic fetching.
- **Rejected tokens**: Any token that does not match `kid` against the trusted key set, uses a disallowed algorithm, or fails any other validation (issuer, audience, lifetime) is rejected with `SecurityTokenInvalidSignatureException` or `SecurityTokenValidationException`.
