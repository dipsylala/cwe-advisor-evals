## Verdict

Confirmed. This is a real, exploitable vulnerability, not a false positive.

`ValidateToken` at line 32 does check a signature, but it checks it against a key the token itself
chose. `IssuerSigningKeyResolver` reads the `jku` header claim out of the unverified token and
fetches a JWKS from that URL, so the attacker supplies both the signature and the key that
validates it. Every other setting on `TokenValidationParameters` - `ValidateIssuer`,
`ValidateAudience`, `ValidateLifetime`, `ValidateIssuerSigningKey` - is satisfied by claims the
attacker also controls, because forging a signature lets them write any issuer, audience, and
expiry they like. The result is a full authentication bypass: an attacker mints a token for any
subject, with any roles, and the service accepts it.

`ValidateIssuerSigningKey = true` is worth calling out because it looks like a mitigation and is
not one here. It validates properties of the key that was resolved (validity period, and for X.509
material the certificate chain); it does not assert that the key belongs to the expected issuer.
A resolver that returns an attacker's key returns it to a check that has nothing trustworthy to
compare it against.

The `kid` filter in the resolver is likewise not a control. The attacker publishes a JWKS whose key
carries whatever `kid` they put in the header, so the filter matches by construction.

## Source

- **Source (attacker-controlled):** `jwt.Header["jku"]` at line 25 - a header claim of the
  incoming, not-yet-verified `token` string.
- **Flow:** line 25 reads `jku` from the raw token; line 26 passes it to
  `JsonWebKeySetFetcher.Fetch`, which retrieves a JWKS from that URL; line 27 returns the matching
  key to the token pipeline.
- **Sink:** line 32, `handler.ValidateToken(token, parameters, out _)`, which performs the
  signature check using the key the resolver returned.

The trust boundary is crossed at line 25: the header of an unverified JWT is untrusted input, and
here it is used to select the trust anchor for verifying that same JWT. The same applies to `x5u`,
`jwk`, and `x5c`, and to `kid` whenever `kid` is treated as a URL or file path - all are
attacker-controlled header claims, and none may select or supply verification key material.

## Fix

The signing keys must come from the issuer's own published key set, discovered from the issuer URL
the application already trusts, and never from the token. Replace the `jku`-driven resolver with a
`ConfigurationManager<OpenIdConnectConfiguration>` bound to the configured authority. It fetches
the OIDC discovery document and JWKS over HTTPS, caches them, and refreshes on a schedule, so key
rotation keeps working without reintroducing token-controlled key selection.

```csharp
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace EvalCases;

public class ReportTokenValidator
{
    private const string Authority = "https://auth.example.com";

    // Static so the discovery document and JWKS are fetched once and cached, then
    // refreshed on the ConfigurationManager's own schedule. Creating one per request
    // would hammer the identity provider and lose rotation state.
    private static readonly ConfigurationManager<OpenIdConnectConfiguration> Configuration =
        new ConfigurationManager<OpenIdConnectConfiguration>(
            Authority.TrimEnd('/') + "/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = true });

    public ClaimsPrincipal ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Authority,
            ValidateAudience = true,
            ValidAudience = "api://reports",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            // Pin the algorithm the issuer actually uses. Without this, the token header
            // can steer verification to a different algorithm than the one intended.
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) => ResolveSigningKeys(kid)
        };

        return handler.ValidateToken(token, parameters, out _);
    }

    private static IEnumerable<SecurityKey> ResolveSigningKeys(string kid)
    {
        var config = Configuration
            .GetConfigurationAsync(CancellationToken.None)
            .GetAwaiter()
            .GetResult();

        var keys = config.SigningKeys;

        // kid narrows the candidate set for performance only; it is an untrusted hint,
        // so an unrecognised or absent kid falls back to trying every published key
        // rather than letting the token name the one that must be used.
        if (!string.IsNullOrEmpty(kid))
        {
            var matches = keys
                .Where(k => string.Equals(k.KeyId, kid, StringComparison.Ordinal))
                .ToList();

            if (matches.Count > 0)
            {
                return matches;
            }

            // An unknown kid usually means the issuer rotated keys since the last fetch.
            Configuration.RequestRefresh();
        }

        return keys;
    }
}
```

`JsonWebKeySetFetcher` is no longer called from this class. Check whether anything else uses it; if
this was its only caller, delete it - a helper that fetches a JWKS from a caller-supplied URL is an
easy way to reintroduce this bug.

Two refinements worth taking if the surrounding code allows:

- **Prefer `JsonWebTokenHandler` over `JwtSecurityTokenHandler`.** `JsonWebTokenHandler` is the
  maintained handler in Microsoft.IdentityModel; `JwtSecurityTokenHandler` is the legacy one. If
  `ValidateToken` can become `async Task<ClaimsPrincipal>`, switch to
  `await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters)` and read `IsValid`,
  `Exception`, and `ClaimsIdentity` off the result. That also lets you set
  `parameters.ConfigurationManager = Configuration` and drop the resolver entirely, and it removes
  the `GetAwaiter().GetResult()` above, which blocks a thread pool thread on the first fetch and
  can deadlock under some synchronization contexts.
- **In an ASP.NET Core host, prefer the JWT bearer middleware.** Setting `Authority` on
  `AddJwtBearer` wires up exactly this discovery-and-cache behaviour and leaves no hand-written key
  resolution to get wrong.

Keep `Microsoft.IdentityModel.*` and `System.IdentityModel.Tokens.Jwt` on a supported release and
check the version in your manifest against the packages' published advisories - this family has
shipped security fixes, and the guidance above assumes a current library.

## Explanation

Signature verification answers one question: was this token signed by a key we already trust? The
original code answers a different and worthless one: was this token signed by the key it says
signed it? Because the `jku` header travels inside the token and is read before any signature is
checked, the attacker chooses the verification key. They generate a keypair, publish the public
half as a JWKS at a URL they control, sign a token of their own design with the private half, and
set `jku` to point at their JWKS. Verification succeeds on the first attempt.

The fix inverts the direction of trust. The application already knows which issuer it accepts - it
is hardcoded as `ValidIssuer` - so that same configured value, not the token, decides where keys
come from. `ConfigurationManager` resolves the authority's discovery document over HTTPS with
`RequireHttps = true`, reads `jwks_uri` from it, and caches the resulting key set. Nothing the
attacker puts in a header can move that lookup.

The remaining details keep the fix from decaying:

- `kid` is retained, but only to pick among keys already fetched from the trusted set. It cannot
  add a key. A `kid` miss triggers `RequestRefresh()` and falls back to trying all published keys,
  so rotation is handled without the token influencing the trust anchor. That fallback is safe
  precisely because every candidate key is one the issuer published.
- `ValidAlgorithms` closes the adjacent algorithm-confusion attack. Without an allowlist, a token
  header can nominate an algorithm the code did not intend; the classic case is `alg: HS256` against
  an RSA public key, where the attacker signs with the public key bytes as an HMAC secret. Current
  Microsoft.IdentityModel versions reject that particular pairing, but pinning the algorithm is the
  durable defence and costs one line.
- `RequireSignedTokens` rejects unsigned (`alg: none`) tokens outright rather than relying on the
  key resolver to fail.
- The `ConfigurationManager` is static because it holds the cache and the refresh clock.
  Constructing one per call re-fetches discovery on every request and turns a rotation-aware cache
  into a per-request outbound HTTP dependency.

To verify: a token signed by the real issuer still validates; a token carrying a `jku` pointing at
an attacker-hosted JWKS and signed with the matching private key must now be rejected with a
signature-key-not-found failure, as must the same token with the `jku` header removed. Assert on
rejection, not on an absence of exceptions - `ValidateToken` throws
`SecurityTokenSignatureKeyNotFoundException` rather than returning null.

The general rule this case illustrates: a token may never nominate the key, the key's location, or
the algorithm used to verify it. Trust anchors are configuration; tokens are input.
