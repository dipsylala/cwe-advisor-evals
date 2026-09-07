## Verdict

Confirmed. Line 26 configures CSRF protection for a JavaScript SPA client using `CookieCsrfTokenRepository.withHttpOnlyFalse()` to expose the token to JavaScript, but omits the required request handler to match the token encoding. Spring Security 6.0+ uses `XorCsrfTokenRequestAttributeHandler` by default, which BREACH-encodes the token server-side. Without pairing the cookie repository with `SpaCsrfTokenRequestHandler`, the token JavaScript reads from the cookie will not match the encoded version the server validates, leaving CSRF protection ineffective.

## Source

**File:** `SecurityConfig.java` line 26

**Code:**
```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

**Data flow:**
1. The SPA reads the CSRF token from the cookie in JavaScript
2. The token is BREACH-encoded server-side by `XorCsrfTokenRequestAttributeHandler` (default in Spring Security 6.0+)
3. JavaScript sends the plain (non-encoded) value read from the cookie
4. Server validation fails because it expects the BREACH-encoded value
5. CSRF protection is ineffective or legitimate requests are rejected

## Fix

**Fixed code:**
```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
```

**Add import:**
```java
import org.springframework.security.web.csrf.SpaCsrfTokenRequestHandler;
```

Alternatively, if using Spring Security 6.1 or later, the `csrf.spa()` shortcut can be used:
```java
.csrf(csrf -> csrf.spa())
```

## Explanation

The vulnerability occurs because `CookieCsrfTokenRepository.withHttpOnlyFalse()` makes the CSRF token readable by JavaScript (necessary for SPA clients that need to send it in request headers or form data), but the default token handler in Spring Security 6.0+ applies BREACH encoding to the token for additional protection against compression attacks. Without an explicit handler that understands this encoding, the plain token JavaScript reads from the cookie will not match the server's validation expectation.

`SpaCsrfTokenRequestHandler` (or the `csrf.spa()` shortcut) ensures that the token encoding is consistent between what the SPA receives and what the server validates. It disables BREACH encoding and uses a consistent, transparent token format that allows JavaScript clients to reliably read and send the token without encoding mismatches.

## Behaviour changes

- **Token format**: The CSRF token will no longer be BREACH-encoded, trading compression-attack protection for SPA compatibility. This is the correct tradeoff for JavaScript clients, which cannot handle encoded tokens reliably.
- **Token transmission**: SPA clients can now successfully read the token from the cookie and include it in request headers (e.g., `X-CSRF-TOKEN`) or form data; server validation will accept it.
- **CSRF protection restored**: Legitimate state-changing requests from the SPA will be accepted; forged cross-site requests will be rejected with 403 Forbidden as expected.
