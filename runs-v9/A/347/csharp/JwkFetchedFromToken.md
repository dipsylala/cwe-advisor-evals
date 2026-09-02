## Verdict

Confirmed. `IssuerSigningKeyResolver` derives the JSON Web Key Set location from the `jku` header of the token being validated, then resolves the trusted signing key from whatever key set is returned. Because the `jku` header is part of the unverified token content, an attacker can craft a token, host their own JWKS at a URL they control, set `jku` to that URL, sign the token with their own private key, and have `JwtSecurityTokenHandler.ValidateToken` accept it as valid. This defeats signature verification: the check ends up validating the token against a key the attacker supplied, not against a key the issuer actually controls.

## Source

`jwt.Header["jku"]` on line 25 — the `jku` (JWK Set URL) claim read out of the JWT header of the token currently being validated, inside the `IssuerSigningKeyResolver` callback.

## Fix

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace EvalCases;

public class ReportTokenValidator
{
    // Loaded once from a fixed, trusted location (e.g. the issuer's
    // well-known discovery document or a securely cached copy), never
    // from anything derived out of the token being validated.
    private readonly JsonWebKeySet _trustedKeySet;

    public ReportTokenValidator(JsonWebKeySet trustedKeySet)
    {
        _trustedKeySet = trustedKeySet;
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
            IssuerSigningKeys = _trustedKeySet.Keys
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

## Explanation

The root cause is trusting attacker-controlled input (the `jku` header of the token under validation) to decide where to fetch the keys that will be used to validate that same token. Any field read out of the JWT header or payload before signature verification succeeds must be treated as untrusted, and must never be used to select or locate the trust anchor used to perform that verification — doing so lets the token vouch for itself.

The fix removes the `IssuerSigningKeyResolver` callback entirely and replaces it with `IssuerSigningKeys`, populated from a fixed, out-of-band source of trusted keys — for example, keys fetched once at startup (or refreshed on a timer) from the issuer's well-known JWKS endpoint whose URL is a hardcoded configuration value, or an `IConfigurationManager<OpenIdConnectConfiguration>` backed by the issuer's discovery document. `kid`-based key selection still happens, but it happens automatically by `JwtSecurityTokenHandler` matching the token's `kid` against the pre-loaded, trusted key set — it never consults anything in the token to decide *where* to look for keys. If a resolver callback is still needed (for example, to support in-place key rotation without a restart), it must select from the same pre-loaded, periodically-refreshed trusted key collection by `kid`, and must never read `jku`, `x5u`, or any other location hint from the token's own header to decide what to fetch or trust.
