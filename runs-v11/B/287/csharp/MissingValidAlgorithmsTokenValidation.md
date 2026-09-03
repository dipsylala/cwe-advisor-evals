## Verdict

Confirmed: CWE-287 (Improper Authentication) - JWT validation does not restrict accepted signing algorithms.

## Source

File: `evals/cases/287/csharp/MissingValidAlgorithmsTokenValidation/Program.cs`, lines 15-26

The `TokenValidationParameters` omits the `ValidAlgorithms` property, allowing the JWT validation middleware to accept any algorithm supported by the signing key type. This permits an attacker to forge a token using an algorithm weaker than the intended one (e.g., swapping HMAC-SHA256 for HMAC-SHA1 or accepting `alg: none` if the key type permits it).

The vulnerable sink is the assignment:
```
options.TokenValidationParameters = new TokenValidationParameters
{
    ...
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes)
    // Missing: ValidAlgorithms
};
```

## Fix

Add `ValidAlgorithms` to explicitly restrict the accepted signing algorithm:

```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["Jwt:Issuer"],
    ValidateAudience = true,
    ValidAudience = builder.Configuration["Jwt:Audience"],
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }
};
```

## Explanation

Without `ValidAlgorithms`, the JWT handler defaults to accepting any algorithm the signing key type supports. A `SymmetricSecurityKey` (used for HMAC signatures) could be coerced to accept weaker algorithms or unintended variants.

By setting `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }`, the token validation enforces that tokens must be signed with exactly HMAC-SHA256. Any token claiming a different algorithm (`HS1`, `HS512`, `alg: none`, or an asymmetric algorithm) will be rejected immediately, closing the algorithm-confusion attack path.

This configuration assumes the issuer signs with HMAC-SHA256; if the issuer uses a different algorithm (e.g., RS256 for RSA), substitute the appropriate constant from `Microsoft.IdentityModel.Tokens.SecurityAlgorithms`.

## Behaviour changes

- Tokens signed with any algorithm other than HMAC-SHA256 are now rejected with a validation error (401 Unauthorized).
- The `TokenValidated` event will not fire for algorithm mismatches; validation fails during the middleware's signature check.
- Existing valid tokens (signed with HMAC-SHA256) continue to validate without change.
- No impact on issuer or audience validation, lifetime checks, or key management.
