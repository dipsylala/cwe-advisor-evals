## Verdict

Exploitable. The CSRF protection is misconfigured: when JavaScript reads the CSRF token from a cookie and echoes it back on state-changing requests, Spring Security's default token handler performs BREACH encoding on the server side. The plain token value the client sends will not match the encoded value the server validates against, causing all protected requests to fail. This effectively disables CSRF protection for the SPA, leaving the application vulnerable to cross-site forgery attacks.

## Source

Line 26 in SecurityConfig.java configures CSRF protection for a SPA with:

```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

The `withHttpOnlyFalse()` call makes the CSRF token readable by JavaScript so the SPA frontend can send it on AJAX requests. However, the default Spring Security 6.0+ token handler (`XorCsrfTokenRequestAttributeHandler`) applies BREACH encoding to the token server-side before validation, creating an encoding mismatch.

## Fix

Add explicit configuration of `SpaCsrfTokenRequestHandler` to handle the token without BREACH encoding:

**Before:**
```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

**After:**
```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new org.springframework.security.web.csrf.SpaCsrfTokenRequestHandler()))
```

If using Spring Security 6.3+, the `csrf.spa()` shortcut provides the same configuration more concisely:

```java
.csrf(csrf -> csrf.spa())
```

## Explanation

`CookieCsrfTokenRepository.withHttpOnlyFalse()` stores the CSRF token in a cookie that JavaScript can read, which is necessary for SPAs that cannot access server-rendered form fields. However, this must be paired with a token handler that uses consistent encoding for what JavaScript reads and what the server validates. The default `XorCsrfTokenRequestAttributeHandler` applies BREACH-resistant encoding to all tokens, so a plain token read from the cookie by JavaScript will not validate. `SpaCsrfTokenRequestHandler` skips the encoding step for cookie-sourced tokens, ensuring the plain token value the JavaScript client echoes matches what the server validates. This preserves CSRF token validation while allowing the SPA to send the token via the `X-CSRF-TOKEN` header or form parameter.

## Behaviour changes

The fixed configuration changes the token encoding behavior: the token held by the server and returned to JavaScript via the cookie will now be in plain form (not BREACH-encoded). This is required for SPA token handling and is the intended contract for this token repository. The token will still be cryptographically random, bound to the session, and validated with constant-time comparison before processing state-changing requests. Framework-provided CSRF validation remains in place and becomes functional rather than silently failing.
