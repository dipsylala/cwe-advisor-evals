## Verdict

Exploitable - CWE-347 (Improper Verification of Cryptographic Signature).

`e:/Github/cwe-advisor/evals/cases/347/csharp/JwkFetchedFromToken/JwkFetchedFromToken.cs`, line 32 (sink), with the defect introduced at lines 22-28.

Confidence: high. The signing key is selected from a URL carried inside the token being validated, so the token authenticates itself: an attacker signs a token with a key pair they own, hosts the matching JWKS at a URL they control, sets `jku` to it, and `ValidateToken` verifies the signature successfully and returns a fully trusted `ClaimsPrincipal` with attacker-chosen claims. `ValidateIssuer`/`ValidateAudience` do not stop this - `iss` and `aud` are also attacker-supplied and are simply set to the expected values. The absence of `ValidAlgorithms` compounds it: the handler accepts whatever algorithm the header declares, so the same resolver also permits an RS256-to-HS256 confusion attack against any key it returns.

## Source

- **Source**: the `jku` header claim of the untrusted, not-yet-verified token - `jwt.Header["jku"]` (line 25), read from the `securityToken` the handler parses before signature verification.
- **Flow**: `ValidateToken(token, ...)` (line 32) parses the token and invokes `IssuerSigningKeyResolver` (line 22) -> `jku` is read from the parsed header (line 25) -> passed to `JsonWebKeySetFetcher.Fetch(jku)` (line 26), which retrieves a JWKS from that attacker-controlled URL -> the returned keys are filtered by `kid` (line 27) and handed back to the handler as trusted signing key material.
- **Sink**: `handler.ValidateToken(token, parameters, out _)` (line 32) - performs the signature check with the key the token nominated.

Sink contract to preserve: returns a `ClaimsPrincipal` that the method returns directly; deliberately discards the `out SecurityToken` via `out _`; throws on failure (`SecurityTokenSignatureKeyNotFoundException` when no key matches the `kid`, `SecurityTokenInvalidSignatureException` on a bad signature, and the issuer/audience/lifetime exceptions), and callers depend on that throw-on-reject behaviour.

`JsonWebKeySetFetcher` is not defined in this file; it is treated as a helper that performs an HTTP GET of a JWKS document at the supplied URL and returns a `JsonWebKeySet`.

## Fix

No library change is required - `System.IdentityModel.Tokens.Jwt` / `Microsoft.IdentityModel.Tokens` are already in use and the weakness is in how they are configured. A dependency review against SCA data is still worth running, but no version bump is part of this fix.

Vulnerable code:

```csharp
var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://auth.example.com",
    ValidateAudience = true,
    ValidAudience = "api://reports",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    // VULNERABLE: the signing key is chosen by the token itself. The `jku` header is
    // read before any signature has been verified, so an attacker points it at a JWKS
    // they host and the token validates against their own key.
    // Also: no ValidAlgorithms, so the header's `alg` decides how the key is used.
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
    private const string JwksUri = "https://auth.example.com/.well-known/jwks.json";

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
            RequireSignedTokens = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            IssuerSigningKeyResolver = (_, _, kid, _) =>
            {
                var keySet = JsonWebKeySetFetcher.Fetch(JwksUri);
                return keySet.Keys.Where(k => k.KeyId == kid);
            }
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

`JwksUri` is shown as a constant to keep the change local; in the real service it should come from the same configuration that supplies `ValidIssuer`, so the two cannot drift apart. Whatever the source, it must be server-side configuration and never a value carried in the token. A JWKS document fetched on every validation is also worth caching behind `ConfigurationManager<OpenIdConnectConfiguration>` (`Microsoft.IdentityModel.Protocols.OpenIdConnect`), which handles refresh and key rollover; that is a separate concern and is not required to close this weakness.

## Explanation

The resolver was letting the token nominate the key used to verify it, which makes the signature check self-referential and therefore meaningless - anyone can produce a token that passes. The fix removes the `jku` read entirely and fetches the key set from `JwksUri`, a location fixed by server configuration, so the only keys that can ever satisfy the signature are the issuer's own; the `kid` from the header is still used, but only to select among keys that are already trusted, which is a safe use of an attacker-controlled value because an unrecognised `kid` yields no key and the handler rejects the token. `ValidAlgorithms` is pinned to RS256 so the header's `alg` can no longer decide how the resolved key is interpreted, closing the RS256-to-HS256 confusion path in which an RSA public key is replayed as an HMAC secret. Together these mean signature verification is performed with a key and an algorithm the application chose, which is what the issuer, audience, and lifetime checks were always relying on in order to mean anything.

## Behaviour changes

- **Key source changed from the token's `jku` to the configured `JwksUri`.** This is the fix itself. Tokens whose `kid` is not present in the issuer's JWKS now throw `SecurityTokenSignatureKeyNotFoundException` where they previously validated against whatever key set the token pointed at. That is the intended rejection, not a regression - but if any legitimate caller was relying on a second issuer's `jku`, it will now fail, and that issuer must be added to trusted configuration explicitly.
- **`ValidAlgorithms` added.** The original accepted any algorithm the header declared. Tokens the issuer legitimately signs with something other than RS256 (RS512, PS256, ES256) will now be rejected; confirm the array against what the issuer actually mints before deploying, and list every algorithm in use.
- **`RequireSignedTokens = true` added.** This restates the library default, so no runtime behaviour changes. It is written out so a later edit to the parameters cannot silently drop it.
- **Resolver lambda parameters `rawToken` and `securityToken` replaced with discards.** They are unused once the header is no longer read. No behaviour change.
- **Return value, the discarded `out SecurityToken`, and the throw-on-failure contract are unchanged.** The method still returns the `ClaimsPrincipal` from the same call at line 32 and still surfaces validation failures as exceptions; only the set of tokens that reach a successful return has narrowed.
- **Not addressed, deliberately:** `RequireExpirationTime` is left at its default, and `JsonWebKeySetFetcher`'s own behaviour (TLS validation, timeouts, caching, error handling) is outside this finding. Neither affects whether the signature weakness is closed.

Assumptions resolved without confirmation: (1) `JsonWebKeySetFetcher.Fetch` is a plain JWKS retrieval helper, since it is not defined in the file under review - if it applies trust logic of its own, re-check that it is not also keyed on token content; (2) the issuer publishes its keys at the conventional `/.well-known/jwks.json` path under `ValidIssuer`, used here as a placeholder for the real configured value; (3) the issuer signs with RS256, inferred from the JWKS-plus-`kid` pattern - verify before deploying.
