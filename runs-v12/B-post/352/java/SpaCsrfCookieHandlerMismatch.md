## Verdict

Confirmed. The CSRF protection is misconfigured for a JavaScript SPA client. The application exposes the CSRF token via a non-HttpOnly cookie to allow client-side access, but fails to configure the token request handler to match the token encoding that JavaScript reads. This mismatch causes legitimate CSRF tokens submitted by the SPA to be rejected.

## Source

`SecurityConfig.java`, line 26:

```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

The source is the security configuration that sets up CSRF protection using `CookieCsrfTokenRepository.withHttpOnlyFalse()` without pairing it with a compatible token request handler.

## Fix

Replace line 26 with:

```java
.csrf(csrf -> csrf.spa())
```

Or for Spring Security versions prior to 6.1, use the explicit handler:

```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
```

The modern `csrf.spa()` shortcut (Spring Security 6.1+) automatically pairs `CookieCsrfTokenRepository.withHttpOnlyFalse()` with `SpaCsrfTokenRequestHandler` to ensure consistent token encoding between client and server.

## Explanation

Spring Security 6.0+ uses `XorCsrfTokenRequestAttributeHandler` by default, which BREACH-encodes the CSRF token server-side before sending it to the client. When `withHttpOnlyFalse()` is used to allow JavaScript to read the token from a cookie, the token value visible to JavaScript is the BREACH-encoded form, but the default handler expects the original unencoded value in the CSRF token submission, causing a mismatch.

The fix uses `SpaCsrfTokenRequestHandler`, which does not BREACH-encode the token value, ensuring the plain token that JavaScript reads from the cookie matches the value the server validates when the token is submitted. This maintains CSRF protection while supporting single-page-application client architectures that require client-side token access.

## Behaviour changes

- CSRF token validation now correctly accepts tokens submitted by JavaScript clients that read the token from the non-HttpOnly cookie.
- Session cookies should still be configured with `SameSite=Strict` or `Lax` as defence-in-depth; this fix does not alter that configuration.
- No change to state-changing endpoint protection, authentication, or session management.
