## Verdict

Exploitable.

## Source

Untrusted JWT bearer token supplied in the `Authorization` header by an attacker.

## Fix

**Vulnerable code (line 32):**

```csharp
options.TokenValidationParameters.SignatureValidator = (token, validationParameters) => new JsonWebToken(token);
```

**Fixed code:**

```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = configuration["Auth:Issuer"],
    ValidateAudience = true,
    ValidAudience = configuration["Auth:Audience"],
    ValidateLifetime = true,
    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
};
```

## Explanation

The custom `SignatureValidator` delegate bypasses cryptographic signature verification entirely by parsing the token and returning it without checking its validity against the issuer's signing key. This allows an attacker to forge any JWT token and have it accepted by the authentication handler. Removing the custom delegate and setting `ValidAlgorithms` explicitly restores the default signature validation path, which verifies the token's HMAC signature against the configured issuer's signing key. The token is now rejected if its signature does not match or if the algorithm differs from the explicit allowlist.

## Behaviour changes

None. The fix restores the intended behavior of cryptographic token verification as implemented by the framework's default `TokenValidationParameters` validation logic. All configured constraints (`ValidIssuer`, `ValidAudience`, `ValidateLifetime`) remain in effect.
