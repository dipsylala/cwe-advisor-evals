## Verdict

exploitable

## Source

The CSRF token stored in a browser cookie via `CookieCsrfTokenRepository.withHttpOnlyFalse()` at line 26 of SecurityConfig.java. This configuration makes the token readable by JavaScript, which is required for single-page applications to include it in request headers or form data. However, the configuration lacks the proper token request handler to validate the token correctly.

## Fix

**Vulnerable code:**
```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

**Fixed code:**
```java
.csrf(csrf -> csrf.spa())
```

Alternatively, for explicit control:
```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
```

## Explanation

When `CookieCsrfTokenRepository.withHttpOnlyFalse()` is used, the CSRF token cookie is accessible to JavaScript so the SPA can read and include it in requests. However, Spring Security 6.0+ by default uses `XorCsrfTokenRequestAttributeHandler` which applies BREACH-encoding to the token. This creates a mismatch: JavaScript reads the plain token value from the cookie, but the server expects the encoded version, causing token validation to fail for legitimate state-changing requests.

Using `csrf.spa()` (or pairing the cookie repository with `SpaCsrfTokenRequestHandler`) ensures that both the token handed to JavaScript and the token validated by the server use the same encoding, eliminating this mismatch while maintaining CSRF protection. `csrf.spa()` is the recommended shortcut that automatically configures `CookieCsrfTokenRepository.withHttpOnlyFalse()` paired with the correct handler.

## Behaviour changes

The fixed code changes the CSRF token handler from the default `XorCsrfTokenRequestAttributeHandler` to `SpaCsrfTokenRequestHandler`. This handler:
- Does not apply BREACH-encoding to the token
- Passes the plain token value to JavaScript clients so that the value they read from the cookie matches the value the server validates
- Continues to generate and validate tokens using cryptographically secure random values and constant-time comparison
- Maintains session binding and token re-issuance at login

State-changing requests (POST, PUT, DELETE) that include the correctly-formatted CSRF token will now be accepted instead of rejected with 403 Forbidden. The session cookie's SameSite attribute should also be configured as Strict or Lax for defence-in-depth.
