## Verdict

**Exploitable.** Confidence: high.

CWE-287 (Improper Authentication) at `CustomSignatureValidatorBypass.cs:32`. The JWT bearer options assign a custom `SignatureValidator` delegate that constructs a `JsonWebToken` from the raw token string and returns it unconditionally, with no signature check. `JwtBearerHandler` treats a non-null `SignatureValidator` as authoritative for signature validation and skips its own key-resolution/signature-verification logic when one is set, so this delegate is the sole gate a presented token passes through for signature integrity.

## Source

- **Source:** the bearer token in the incoming request's `Authorization: Bearer <token>` header, read by the ASP.NET Core JWT bearer authentication middleware registered via `AddJwtBearer` (attacker-controlled - any caller can supply an arbitrary string here).
- **Sink:** `options.TokenValidationParameters.SignatureValidator = (token, validationParameters) => new JsonWebToken(token);` (line 32). `JsonWebToken`'s constructor only base64url-decodes and JSON-parses the header/payload/signature segments; it performs no cryptographic verification. Because the delegate returns successfully for any structurally well-formed JWT, the middleware accepts the token, builds a `ClaimsPrincipal` from its (attacker-supplied) claims, and authenticates the request - `ValidateIssuer`/`ValidateAudience`/`ValidateLifetime` are checked only against claims the attacker also controls, since nothing has confirmed those claims came from the real issuer.
- No validation or constraint sits between the header and this delegate, so the path is live: an attacker can mint a token with an arbitrary `iss`/`aud`/`sub`/role claims, matching whatever `ValidIssuer`/`ValidAudience` the app expects, and be authenticated as any identity.

## Fix

### File: CustomSignatureValidatorBypass.cs

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ContosoApi.Authentication
{
    // Registers bearer-token authentication for the API. Targets .NET 8, where the
    // JWT bearer handler validates tokens through JsonWebTokenHandler by default.
    public static class JwtBearerSetup
    {
        public static IServiceCollection AddApiJwtBearer(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = configuration["Auth:Authority"];
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = configuration["Auth:Issuer"],
                        ValidateAudience = true,
                        ValidAudience = configuration["Auth:Audience"],
                        ValidateLifetime = true,
                    };
                });

            return services;
        }
    }
}
```

## Explanation

The vulnerable line assigned a custom `SignatureValidator` that hands back a parsed-but-unverified `JsonWebToken`, which fully bypasses `JwtBearerHandler`'s built-in signature verification for every request through this scheme. The fix removes that delegate (and its stale explanatory comment) and leaves `TokenValidationParameters` to fall through to the default validator, which resolves the issuer's real signing keys from the OpenID Connect discovery document at `options.Authority` (already configured) and cryptographically verifies the signature before the existing `ValidateIssuer`, `ValidateAudience`, and `ValidateLifetime` checks run. `ValidateIssuerSigningKey` was never overridden in the original file, so it retains its framework default of `true` in both versions - the default validator was always available, it was simply being shadowed by the custom delegate. This directly closes the CWE-287 sink named in the finding and matches the local guidance's rule to never assign a `SignatureValidator`/`TokenReader` override that returns a token without verifying it.

## Behaviour changes

- **Removed:** the `SignatureValidator` delegate and its preceding comment block. This is the fix itself, not incidental - it is the exact sink the finding names.
- **Resulting behaviour change (intended):** tokens that previously authenticated with no valid signature (including any malformed or legacy-format token the delegate was added to tolerate) will now be rejected by the default validator with `401 Unauthorized` unless they carry a genuine signature from a key published at `Auth:Authority`'s discovery endpoint. This is the required consequence of closing the bypass, not a side effect - the code comment states the delegate exists only to admit tokens the default handler was rejecting.
- **Not changed:** `ValidateIssuer`, `ValidIssuer`, `ValidateAudience`, `ValidAudience`, `ValidateLifetime`, and `options.Authority` are all left exactly as configured; `ValidateIssuerSigningKey` remains at its unset default (`true`) in both versions.
- **Considered and not applied:** the C# guidance also recommends pinning `TokenValidationParameters.ValidAlgorithms` to the issuer's exact signing algorithm(s) as defence-in-depth against algorithm confusion. This file does not evidence which algorithm the issuer at `Auth:Authority` actually signs with, and supplying a guessed value risks rejecting legitimate tokens; it is left as a follow-up hardening item to be set once the issuer's algorithm is confirmed, rather than guessed here.
- **Verification:** the fixed file was copied into a scratch ASP.NET Core project (`dotnet new web`, target `net10.0`) referencing `Microsoft.AspNetCore.Authentication.JwtBearer` 10.0.0 and `Microsoft.IdentityModel.JsonWebTokens` 8.22.0, and built with `dotnet build`. Result: build succeeded, 0 warnings, 0 errors.
