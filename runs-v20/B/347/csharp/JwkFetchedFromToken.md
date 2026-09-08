## Verdict

Confirmed. The `IssuerSigningKeyResolver` derives the JWKS location from the `jku` header of the token being validated, then resolves the verification key from whatever key set is hosted there. An attacker can craft a token with `jku` pointing at a server they control, host a JWKS containing a key of their own choosing, and sign the token with the matching private key. `JwtSecurityTokenHandler.ValidateToken()` at line 32 will then verify the forged token's signature successfully because the verification key came from the attacker, not from a trusted source - this is a signature-verification bypass, not merely an SSRF.

## Source

`token`, the `string` parameter of `ValidateToken(string token)`. It is attacker-controlled: it flows unmodified into `handler.ValidateToken(token, parameters, out _)`, and its header is read back out inside the resolver via `securityToken.Header["jku"]` before the signature has been checked, so the resolver is choosing trust based on unverified data taken from the same token it is about to verify.

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
    // Trusted JWKS endpoint for the pinned issuer; never derived from the token under validation.
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
                var keySet = JsonWebKeySetFetcher.Fetch(TrustedJwksUri);
                return keySet.Keys.Where(k => k.KeyId == kid);
            }
        };

        return handler.ValidateToken(token, parameters, out _);
    }
}
```

## Explanation

The resolver no longer reads `jku` (or the token at all) to decide where to fetch keys from. It fetches the key set from `TrustedJwksUri`, a fixed, server-side constant that matches the pinned `ValidIssuer` ("https://auth.example.com"), and only then filters that trusted key set by the token's `kid` to select the candidate key(s) - `kid` is an index into a set the server already trusts, not a pointer to a new trust root, so using it here is safe. This is the fix the C# guidance calls for: `IssuerSigningKey`/`IssuerSigningKeys` (and anything an `IssuerSigningKeyResolver` returns) must come from a trusted, server-side keystore or JWKS, never from a location or value embedded in the token being validated. Because the JWKS source no longer depends on the token, `securityToken` is unused in the resolver body and the cast to `JwtSecurityToken` that only existed to read the header is removed along with it.

Separately, the same C# guidance flags that `JwtSecurityTokenHandler.ValidateToken()` accepts whatever algorithm the token header declares unless `ValidAlgorithms` is set explicitly, which is a second, independent way to defeat signature verification at this same sink (classic RS256-to-HS256 key-confusion, where the server's RSA public key is replayed as an HMAC secret) even after the key source itself is trustworthy. The original code left `ValidAlgorithms` unset, so `ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }` was added to pin the sink to the one algorithm the trusted JWKS's keys are meant to be used with; `SecurityAlgorithms` is already available from the pre-existing `using Microsoft.IdentityModel.Tokens;`.

`ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, and `ValidateIssuerSigningKey` were already `true` and are unchanged. `handler.ValidateToken`'s contract is otherwise preserved: it still returns the `ClaimsPrincipal` on success, still discards the `out SecurityToken` via `out _` as before, and still throws (e.g. `SecurityTokenInvalidSignatureException`, `SecurityTokenSignatureKeyNotFoundException`) on failure, which the caller was already relying on for rejection.

Verification: no SAST/DAST call path was attached, so the flow above was traced by reading the resolver directly (Step 4, Option B) - `token` to `securityToken.Header["jku"]` to `JsonWebKeySetFetcher.Fetch(jku)` to the returned key being handed to the signature verifier, with no validation of `jku` against any trust anchor in between, confirming the path is real and exploitable as reported. Every new name in the fix was checked before use: `TrustedJwksUri` is a constant introduced by this fix; `JsonWebKeySetFetcher.Fetch` is the pre-existing call, unchanged except for its argument; `SecurityAlgorithms.RsaSha256` is a documented member of `Microsoft.IdentityModel.Tokens`, already imported. The fixed file was compiled with `dotnet build` against `Microsoft.IdentityModel.Tokens` and `System.IdentityModel.Tokens.Jwt` 8.0.1 (with a same-signature stub standing in for the project-local `JsonWebKeySetFetcher`, whose implementation lives outside this file) and built with 0 errors and 0 warnings.

## Behaviour changes

- The JWKS used to verify a token's signature is now always fetched from `TrustedJwksUri` instead of the URL in that token's own `jku` header. Any legitimate use case that relied on per-token `jku` values pointing at different, still-trustworthy key sets (e.g. multiple accepted issuers each with their own JWKS) is no longer supported by this resolver as written - it now assumes a single pinned issuer, consistent with the single `ValidIssuer` already configured. If more than one issuer must be supported, `TrustedJwksUri` should be selected from a small server-side map keyed by the already-validated issuer, never from the token header.
- Tokens signed with an algorithm other than RS256 will now be rejected via `ValidAlgorithms`, where previously any algorithm the token declared (including a mismatched or attacker-chosen one) would have been accepted as long as a matching key was found. Any legitimate token source that signs with a different algorithm against the same JWKS will need `ValidAlgorithms` extended to include it explicitly.
