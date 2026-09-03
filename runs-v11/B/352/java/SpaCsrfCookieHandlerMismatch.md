## Verdict

The CSRF protection is incomplete. The code enables cookie-based CSRF tokens readable by JavaScript but fails to configure the corresponding server-side token handler, causing a mismatch between the token JavaScript reads from the cookie and the encoded value the server expects.

## Source

Line 26 of SecurityConfig.java configures `CookieCsrfTokenRepository.withHttpOnlyFalse()` to allow JavaScript to read the CSRF token from a cookie. This is the correct approach for a single-page application frontend that must include the token in AJAX requests.

## Fix

Add `SpaCsrfTokenRequestHandler` to pair with the cookie repository. Replace line 26:

```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

With:

```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
```

And add the import at the top of the file:

```java
import org.springframework.security.web.csrf.SpaCsrfTokenRequestHandler;
```

**Alternative (Spring Security 6.1+)**: Use the simpler `csrf.spa()` shortcut:

```java
.csrf(csrf -> csrf.spa())
```

## Explanation

Spring Security 6.0+ uses `XorCsrfTokenRequestAttributeHandler` by default, which BREACH-encodes the token server-side. When `withHttpOnlyFalse()` exposes the raw cookie value to JavaScript, it sends that unencoded value back to the server, but the default handler expects the encoded form. This mismatch causes legitimate AJAX requests to be rejected as CSRF forgeries.

`SpaCsrfTokenRequestHandler` ensures both the cookie value handed to JavaScript and the server-side validation use the same encoding, eliminating the mismatch. The alternative `csrf.spa()` shortcut provides the same fix in a single method call for Spring Security 6.1+.

## Behaviour changes

- AJAX requests from the SPA client that previously failed validation due to token mismatch will now succeed.
- CSRF protection remains fully functional—the same synchronizer token pattern is enforced, just with correct encoding alignment.
- No state-changing operation is affected; only the token validation now matches what the frontend sends.
